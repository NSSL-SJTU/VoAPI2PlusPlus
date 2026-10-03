import hashlib
import asyncio
import json
import logging
import re
from collections import deque
from itertools import count
from time import perf_counter
from typing import Any
from urllib.parse import urljoin, urlparse
from weakref import WeakSet

from playwright.async_api import async_playwright, Dialog, TimeoutError as PlaywrightTimeoutError

from vuln.xss_registry import XSSRegistry
from vuln.recorder import VulnRecorder


logger = logging.getLogger(__name__)

_HIGH_VALUE_NAV_TERMS = (
    "admin", "dashboard", "manage", "management", "setting", "settings",
    "configuration", "configure", "library", "libraries", "metadata",
    "plugin", "plugins", "repository", "repositories", "device", "devices",
    "collection", "collections", "playlist", "playlists", "user", "users",
    "profile", "profiles", "item", "items", "detail", "details", "list",
)
_LOW_VALUE_NAV_TERMS = (
    "cast", "syncplay", "search", "favorite", "favorites", "latest",
    "next up", "home",
)
_STATEFUL_BUTTON_RE = re.compile(
    r"\b(next|load\s*more|more|details?|view|expand|open|show|tab|page|settings|edit)\b"
    r"|下一页|加载更多|更多|详情|展开|打开|查看|设置|编辑",
    re.IGNORECASE,
)
_NON_NAV_ACTION_RE = re.compile(
    r"\b(save|submit|confirm|cancel|close|block|clear|update|invite|upload|regenerate)\b"
    r"|保存|提交|确认|取消|关闭|上传|邀请",
    re.IGNORECASE,
)
# Broad cursor:pointer / double-click crawling reaches controls behind SPA navigation,
# but must never invoke a destructive one during a live scan. A control whose label
# matches this is never clicked or double-clicked. Bilingual; CJK terms take no \b.
_DANGEROUS_ACTION_RE = re.compile(
    r"\b(delete|remove|drop|truncate|logout|log\s*out|sign\s*out|log\s*off|"
    r"reset|revoke|disable|deactivate|uninstall|destroy|wipe|deregister|unregister)\b"
    r"|删除|移除|删掉|清空|清除|重置|注销|退出登录|登出|停用|禁用|卸载|销毁|作废|撤销",
    re.IGNORECASE,
)
_ALERT_HOOK_JS = r"""
(() => {
  if (window.__voapiHookInstalled) return;
  window.__voapiHookInstalled = true;
  window.__voapiAlerts = window.__voapiAlerts || [];
  for (const name of ["alert", "confirm", "prompt"]) {
    window["__voapiOriginal" + name] = window[name];
    window[name] = function(message) {
      const event = {kind: name, message: String(message), url: location.href};
      try { event.topUrl = window.top.location.href; } catch (_) {}
      window.__voapiAlerts.push(event);
      if (typeof window.__voapiReportAlert === "function") {
        try {
          Promise.resolve(window.__voapiReportAlert(event)).then(() => {
            const queue = window.__voapiAlerts;
            const index = queue.indexOf(event);
            if (index >= 0) queue.splice(index, 1);
          }).catch(() => {}); // Preserve the queue if transport fails.
        } catch (_) {}
      }
      if (name === "confirm") return true;
      if (name === "prompt") return "";
    };
  }
})();
"""

_DOM_PROBE_JS = r"""
(ids) => {
  const requested = new Set(ids);
  const customIds = ids.filter(id => !/^xss_[0-9a-f]{8}$/.test(id));
  const found = new Set();
  const evidence = [];
  const actions = [];
  const links = [];
  const counts = new Map();
  const geometry = new WeakMap();
  const paths = new WeakMap();
  const siblingIndexes = new WeakMap();
  const controlSelector = "button,[role=button],a[href],summary,input";

  function matches(value) {
    if (!value) return [];
    const hits = new Set((value.match(/xss_[0-9a-f]{8}(?![0-9a-f])/g) || [])
      .filter(id => requested.has(id)));
    for (const id of customIds) if (value.includes(id)) hits.add(id);
    return hits;
  }

  function box(el) {
    if (!geometry.has(el)) {
      const rect = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      geometry.set(el, {rect, visible: rect.width >= 4 && rect.height >= 4 &&
        style.display !== "none" && style.visibility !== "hidden" &&
        style.pointerEvents !== "none"});
    }
    return geometry.get(el);
  }

  function label(el) {
    const control = el.closest(controlSelector) || el;
    return (control.innerText || control.getAttribute("aria-label") ||
      control.getAttribute("title") || control.value || "").trim();
  }

  function metadata(el) {
    const control = el.closest(controlSelector) || el;
    return {
      tag: el.tagName, text: label(el).slice(0, 160), href: el.href || "",
      ariaLabel: control.getAttribute("aria-label") || "",
      title: control.getAttribute("title") || "", value: control.value || "",
      role: el.getAttribute("role") || "", type: control.type || "",
      inForm: Boolean(control.form),
      disabled: Boolean(control.disabled || control.getAttribute("aria-disabled") === "true" ||
        control.classList.contains("disabled") || control.closest("[disabled]"))
    };
  }

  function cssPath(el) {
    if (paths.has(el)) return paths.get(el);
    const original = el;
    const parts = [];
    let anchored = false;
    while (el && el !== document.body && el.nodeType === Node.ELEMENT_NODE) {
      if (el.id && document.querySelectorAll("#" + CSS.escape(el.id)).length === 1) {
        parts.unshift(el.tagName.toLowerCase() + "#" + CSS.escape(el.id));
        anchored = true;
        break;
      }
      if (!siblingIndexes.has(el) && el.parentElement) {
        const indexes = new Map();
        for (const child of el.parentElement.children) {
          const index = (indexes.get(child.tagName) || 0) + 1;
          indexes.set(child.tagName, index);
          siblingIndexes.set(child, index);
        }
      }
      parts.unshift(el.tagName.toLowerCase() + ":nth-of-type(" + (siblingIndexes.get(el) || 1) + ")");
      el = el.parentElement;
    }
    const path = (anchored ? "" : "body > ") + parts.join(" > ");
    paths.set(original, path);
    return path;
  }

  function pushAction(kind, el, score, xssId = "") {
    if (!el || !box(el).visible) return;
    const data = metadata(el);
    if (data.disabled) return;
    const rect = box(el).rect;
    actions.push({...data, kind, score, xssId, selector: cssPath(el),
      x: rect.left + rect.width / 2, y: rect.top + Math.min(rect.height / 2, 30),
      inViewport: rect.right > 0 && rect.bottom > 0 && rect.left < innerWidth && rect.top < innerHeight});
  }

  function observe(el, value, context) {
    for (const id of matches(value)) {
      found.add(id);
      if ((counts.get(id) || 0) >= 25) continue;
      counts.set(id, (counts.get(id) || 0) + 1);
      const container = el.closest("tr,[role=row],li,.row,.card,.box");
      const link = el.closest("a[href]") || (container && container.querySelector("a[href]"));
      evidence.push({id, tag: el.tagName, context, text: value.slice(0, 180),
        href: link ? link.href : "", link: link ? metadata(link) : null,
        outer: el.outerHTML.slice(0, 320)});
      pushAction("evidence-link", link, 200, id);
      pushAction("evidence-container", container, 120, id);
    }
  }

  // Inspect direct text and attributes once, rather than serializing every ancestor per ID.
  const root = document.documentElement;
  if (requested.size && root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    let node = root;
    do {
      if (node.nodeType === Node.TEXT_NODE && node.parentElement) {
        const context = node.parentElement.tagName === "SCRIPT" ? "script-text" :
          (/<[a-z!]/i.test(node.nodeValue) ? "escaped-text" : "contains-id");
        observe(node.parentElement, node.nodeValue || "", context);
      } else if (node.nodeType === Node.ELEMENT_NODE) {
        for (const attr of node.attributes) {
          const context = /^on/i.test(attr.name) ? "event-attribute" :
            (/^(src|href|action)$/i.test(attr.name) ? "attribute-url" : "attribute");
          observe(node, attr.value, context);
        }
      }
    } while ((node = walker.nextNode()));
  }

  for (const link of document.querySelectorAll("a[href]")) {
    links.push(metadata(link)); // Discovery is independent of visibility and click budgets.
    pushAction("link", link, 20);
  }
  const controls = new Set(document.querySelectorAll(
    "button,[role=button],[role=tab],[role=treeitem],[role=menuitem],summary,[tabindex],[onclick],input[type=button],input[type=submit]"
  ));
  for (const el of document.querySelectorAll("body *")) {
    if (getComputedStyle(el).cursor === "pointer") controls.add(el);
  }
  for (const el of controls) {
    if (el.tagName === "A" && el.href) continue;
    const parent = el.parentElement && el.parentElement.closest(controlSelector);
    if (parent && (controls.has(parent) || parent.href)) continue;
    const score = /details|view|more|expand|open|show|next|page|tab|settings/i.test(label(el)) ? 30 : 10;
    pushAction("button", el, score);
  }
  const uniqueActions = [];
  const seen = new Map();
  for (const action of actions.sort((a, b) => b.score - a.score)) {
    if (seen.has(action.selector)) {
      if (action.kind === "button") seen.get(action.selector).interactive = true;
      continue;
    }
    action.interactive = action.kind === "button";
    seen.set(action.selector, action);
    uniqueActions.push(action);
  }
  const text = document.body ? document.body.innerText : "";
  let hash = 0;
  for (let i = 0; i < text.length; i++) hash = ((hash << 5) - hash + text.charCodeAt(i)) | 0;
  return {url: location.href, title: document.title, contentHash: String(hash),
    idsFound: [...found], evidence, links, actions: uniqueActions};
}
"""


def parse_cookie_str(cookie_str: str, domain: str) -> list[dict]:
    cookies = []
    for item in cookie_str.split(";"):
        if "=" in item:
            name, value = item.strip().split("=", 1)
            cookies.append({
                "name": name,
                "value": value,
                "domain": domain,
                "path": "/",
            })
    return cookies


class XSSWalker:
    def __init__(
        self,
        home_url: str,
        cookie_str: str,
        domain: str,
        xss_registry: XSSRegistry,
        vuln_recorder: VulnRecorder,
        max_steps: int = 500,
        max_actions_per_page: int = 12,
        headless: bool = True,
        settle_ms: int = 700,
        local_storage: dict[str, str] | None = None,
        max_noop_clicks_per_page: int = 8,
        seed_urls: list[str] | None = None,
        parallel_url_workers: int = 1,
        parallel_url_budget: int = 0,
        button_crawl_mode: str = "navigation",
        max_stateful_pages: int = 50,
    ):
        self.home_url = home_url
        self.cookie_str = cookie_str
        self.domain = domain
        self.xss_registry = xss_registry
        self.vuln_recorder = vuln_recorder
        self.max_steps = max_steps
        self.max_actions_per_page = max_actions_per_page
        self.headless = headless
        self.settle_ms = settle_ms
        self.local_storage = local_storage or {}
        self.max_noop_clicks_per_page = max_noop_clicks_per_page
        self.home_origin = self._origin(home_url)
        self.priority_terms = self._build_priority_terms()
        self.seed_urls = seed_urls or []
        self.parallel_url_workers = max(1, int(parallel_url_workers or 1))
        self.parallel_url_budget = max(0, int(parallel_url_budget or 0))
        if self.parallel_url_workers > 1 and self.parallel_url_budget <= 0:
            # Asking for workers without a budget silently yields a serial crawl,
            # because _run_parallel_url_phase bails on budget <= 0.
            logger.warning(
                "parallel_url_workers=%d has no effect while parallel_url_budget=0; "
                "crawling serially. Set parallel_url_budget (e.g. max_steps//2) to "
                "actually run workers in parallel.",
                self.parallel_url_workers,
            )
        self.button_crawl_mode = (button_crawl_mode or "navigation").lower()
        self.max_stateful_pages = max(0, int(max_stateful_pages or 0))
        self.visited_urls: set[str] = set()
        self.queued_urls: set[str] = set()
        self.stateful_click_urls: deque[str] = deque()
        self.queued_stateful_click_urls: set[str] = set()
        self.explored_stateful_click_urls: set[str] = set()
        self.clicked_actions: set[str] = set()
        self.swept_states: set[str] = set()
        self.sweep_pending: dict[str, str] = {}
        self.triggered_ids: list[str] = []
        self.visible_ids: set[str] = set()
        self.unreachable_url_count = 0
        self.probed_urls: set[str] = set()
        self.probe_count = 0
        self.probe_ms = 0.0
        self.peak_active_url_workers = 0
        self._active_url_workers = 0
        self._attached_pages: WeakSet = WeakSet()
        self._confirmation_event: asyncio.Event | None = None
        self.stop_reason = "not_started"

    def _record_alert(self, msg: str, url: str, *, top_url: str = "", kind: str = "alert") -> bool:
        xss_id = self.xss_registry.find_id_in_text(msg)
        if xss_id:
            record = self.xss_registry.lookup(xss_id)
            if record:
                if xss_id in self.triggered_ids:
                    return False
                self.triggered_ids.append(xss_id)
                logger.info(
                    "XSS triggered! ID=%s method=%s url=%s param=%s page=%s",
                    xss_id, record.api_method, record.api_url, record.param_name, url,
                )
                vuln_content = (
                    f"API Vul Type: XSS\n"
                    f"Vul API Url: {record.api_url}\n"
                    f"Vul API Method: {record.api_method}\n"
                    f"API Vul Param: {record.param_name}\n"
                    f"API Test Payload: {record.attack_payload}\n"
                    f"XSS ID: {xss_id}\n"
                    f"Triggered On Page: {url}\n"
                    f"Alert Message: {msg}\n"
                    f"Main Page URL: {top_url or url}\n"
                    f"Signal Kind: {kind}\n"
                    "Confirmed By: browser-walker\n"
                )
                vuln_dir = self.vuln_recorder.root / "xss"
                vuln_dir.mkdir(parents=True, exist_ok=True)
                safe_url = record.api_url.replace("/", "!")
                vuln_file = vuln_dir / f"{safe_url}!{record.param_name}.txt"
                with vuln_file.open("a") as f:
                    f.write(vuln_content + "\n")
                if self._confirmation_event is not None and self._all_triggered():
                    self._confirmation_event.set()
                return True
        else:
            logger.debug("Alert without matching XSS ID: %s (page=%s)", msg, url)
        return False

    async def handle_dialog(self, dialog: Dialog):
        self._record_alert(dialog.message, dialog.page.url)

        await dialog.accept()

    def summary(self) -> dict[str, Any]:
        all_ids = set(self.xss_registry.all_ids())
        confirmed = set(self.triggered_ids)
        rejected = (self.visible_ids & all_ids) - confirmed
        unreachable = all_ids - confirmed - rejected
        return {
            "summary_schema_version": 2,
            "registered": len(all_ids),
            "confirmed": len(confirmed),
            "observed_unconfirmed": len(rejected),
            "observed_unconfirmed_ids": sorted(rejected),
            "not_observed": len(unreachable),
            "not_observed_ids": sorted(unreachable),
            "legacy_field_semantics": {
                "rejected": "alias of observed_unconfirmed; does not rule out XSS",
                "unreachable": "alias of not_observed; does not establish URL reachability",
                "visible_ids": "IDs observed in the DOM, including hidden content",
            },
            "rejected": len(rejected),
            "unreachable": len(unreachable),
            "triggered": len(self.triggered_ids),
            "triggered_ids": list(self.triggered_ids),
            "rejected_ids": sorted(rejected),
            "unreachable_ids": sorted(unreachable),
            "visible_ids": sorted(self.visible_ids & all_ids),
            "visited_count": len(self.visited_urls),
            "clicked_count": len(self.clicked_actions),
            "unreachable_url_count": self.unreachable_url_count,
            "parallel_url_workers": self.parallel_url_workers,
            "parallel_url_budget": self.parallel_url_budget,
            "button_crawl_mode": self.button_crawl_mode,
            "stateful_click_pages": len(self.explored_stateful_click_urls),
            "probed_url_count": len(self.probed_urls),
            "probe_count": self.probe_count,
            "probe_ms": round(self.probe_ms, 3),
            "peak_active_url_workers": self.peak_active_url_workers,
            "stop_reason": self.stop_reason,
            "pending_url_count": len(self.queued_urls - self.visited_urls),
            "pending_interaction_count": len(self.stateful_click_urls),
        }

    def _normalize_url(self, url: str) -> str:
        # Keep query strings and hash routes; Jellyfin-like SPAs use hashes as routes.
        parsed = urlparse(self._resolve_url(url))
        # Only normalize an empty origin path. A trailing slash in a path, query
        # value or hash route can identify a different resource.
        return parsed._replace(path=parsed.path or "/").geturl()

    def _resolve_url(self, url: str) -> str:
        try:
            return urljoin(self.home_url, url or "")
        except ValueError as exc:
            logger.debug("XSS Walker: unparseable URL %r dropped: %s", url, exc)
            return ""

    def _origin(self, url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _same_origin(self, url: str) -> bool:
        if not url:
            return False
        try:
            return self._origin(self._resolve_url(url)) == self.home_origin
        except Exception:
            return False

    def _action_signature(
        self,
        page_url: str,
        action: dict[str, Any],
        page_state: str = "",
    ) -> str:
        raw_sig = "|".join([
            self._normalize_url(page_url),
            page_state,
            action.get("kind", ""),
            action.get("tag", ""),
            action.get("href", ""),
            action.get("ariaLabel", ""),
            action.get("value", ""),
            action.get("xssId", ""),
            action.get("text", ""),
            action.get("selector", ""),
            action.get("frameKey", ""),
            str(round(float(action.get("x", 0)))),
            str(round(float(action.get("y", 0)))),
        ])
        return hashlib.md5(raw_sig.encode()).hexdigest()

    def _report_signature(self, report: dict[str, Any]) -> str:
        actions = []
        for action in report.get("actions", [])[:100]:
            if not action.get("inViewport", True):
                continue
            actions.append((
                action.get("kind", ""),
                action.get("tag", ""),
                action.get("href", ""),
                action.get("xssId", ""),
                action.get("text", ""),
                action.get("frameKey", ""),
                round(float(action.get("x", 0)) / 20),
                round(float(action.get("y", 0)) / 20),
            ))
        evidence = [
            (
                item.get("id", ""),
                item.get("context", ""),
                item.get("href", ""),
            )
            for item in report.get("evidence", [])[:100]
        ]
        raw_sig = json.dumps(
            {
                "url": self._normalize_url(report.get("url", "")),
                "contentHash": report.get("contentHash", ""),
                "ids": sorted(report.get("idsFound", [])),
                "actions": actions,
                "evidence": sorted(evidence),
            },
            sort_keys=True,
        )
        return hashlib.md5(raw_sig.encode()).hexdigest()

    def _remaining_ids(self) -> list[str]:
        triggered = set(self.triggered_ids)
        return [
            xss_id for xss_id in self.xss_registry.all_ids()
            if xss_id not in triggered
        ]

    def _action_mentions_triggered_id(self, action: dict[str, Any]) -> bool:
        if not self.triggered_ids:
            return False
        haystack = " ".join([
            action.get("xssId", ""),
            action.get("href", ""),
            action.get("text", ""),
        ])
        return any(xss_id in haystack for xss_id in self.triggered_ids)

    def _all_triggered(self) -> bool:
        return set(self.triggered_ids) >= set(self.xss_registry.all_ids())

    def _remember_report_ids(self, report: dict[str, Any]) -> None:
        all_ids = set(self.xss_registry.all_ids())
        ids = set(report.get("idsFound", []) or [])
        for item in report.get("evidence", []) or []:
            xss_id = item.get("id") or ""
            if xss_id:
                ids.add(xss_id)
        self.visible_ids.update(ids & all_ids)

    def _split_terms(self, value: str) -> set[str]:
        spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value or "")
        return {
            part.lower()
            for part in re.split(r"[^A-Za-z0-9]+", spaced)
            if len(part) >= 3
        }

    def _build_priority_terms(self) -> set[str]:
        terms: set[str] = set()
        for xss_id in self.xss_registry.all_ids():
            record = self.xss_registry.lookup(xss_id)
            if not record:
                continue
            for raw in (record.api_url, record.param_name):
                for term in self._split_terms(raw):
                    terms.add(term)
                    if term.endswith("s") and len(term) > 4:
                        terms.add(term[:-1])
        return terms

    def _priority_score(self, *values: str) -> int:
        haystack = " ".join(v or "" for v in values).lower()
        score = 0
        for term in self.priority_terms:
            if term in haystack:
                score += 100
        for term in _HIGH_VALUE_NAV_TERMS:
            if term in haystack:
                score += 20
        for term in _LOW_VALUE_NAV_TERMS:
            if term in haystack:
                score -= 10
        return score

    def _action_priority(self, action: dict[str, Any]) -> int:
        base_score = int(action.get("score") or 0)
        return base_score + self._priority_score(
            action.get("text", ""),
            action.get("href", ""),
            action.get("ariaLabel", ""),
            action.get("kind", ""),
        )

    def _is_button_action(self, action: dict[str, Any]) -> bool:
        tag = (action.get("tag") or "").upper()
        kind = action.get("kind") or ""
        role = (action.get("role") or "").lower()
        if tag == "A" and action.get("href"):
            return False
        return kind == "button" or tag in {"BUTTON", "SUMMARY", "INPUT"} or role == "button"

    def _stateful_action_text(self, action: dict[str, Any]) -> str:
        return " ".join([
            action.get("text", ""),
            action.get("ariaLabel", ""),
            action.get("value", ""),
            action.get("role", ""),
            action.get("href", ""),
        ])

    def _is_dangerous_action(self, action: dict[str, Any]) -> bool:
        """A control whose visible label reads destructive (delete/logout/drop/...).

        Checked against the label sources only (text/ariaLabel/value/title), never href
        or role, so a benign link with 'delete' in its path is not blocked.
        """
        label = " ".join([
            action.get("text", ""),
            action.get("ariaLabel", ""),
            action.get("value", ""),
            action.get("title", ""),
        ])
        return bool(_DANGEROUS_ACTION_RE.search(label))

    def _allow_action(self, action: dict[str, Any], *, navigation: bool = False) -> bool:
        if action.get("disabled") or self._is_dangerous_action(action):
            return False
        label = " ".join(str(action.get(key) or "") for key in ("text", "ariaLabel", "title", "value"))
        if _NON_NAV_ACTION_RE.search(label):
            return False
        if action.get("inForm") and action.get("type") in {"submit", "reset"}:
            return False
        href = action.get("href") or ""
        if href:
            return self._same_origin(href)
        return not navigation and self.button_crawl_mode != "off"

    def _is_stateful_button_action(self, action: dict[str, Any]) -> bool:
        if not self._allow_action(action):
            return False
        if action.get("href"):
            return False
        if not self._is_button_action(action):
            return False
        if action.get("disabled"):
            return False
        if self.button_crawl_mode == "safe":
            return True
        return bool(_STATEFUL_BUTTON_RE.search(self._stateful_action_text(action)))

    def _should_revisit_page_for_action(self, action: dict[str, Any]) -> bool:
        if not self._is_stateful_button_action(action):
            return False
        if self.button_crawl_mode == "safe":
            return True
        return not action.get("inViewport", True)

    def _action_allowed_by_viewport(self, action: dict[str, Any]) -> bool:
        if action.get("inViewport", True):
            return True
        return self._is_stateful_button_action(action)

    def _select_actions(
        self,
        actions: list[dict[str, Any]],
        stateful_only: bool = False,
        page_url: str = "",
        page_state: str = "",
    ) -> list[dict[str, Any]]:
        remaining_ids = set(self._remaining_ids())
        evidence_by_id: dict[str, list[dict[str, Any]]] = {}
        generic_actions: list[dict[str, Any]] = []

        for action in actions:
            if not self._allow_action(action):
                continue
            if page_url and self._action_signature(page_url, action, page_state) in self.clicked_actions:
                continue
            if not self._action_allowed_by_viewport(action):
                continue
            if self._action_mentions_triggered_id(action):
                continue
            xss_id = action.get("xssId") or ""
            if xss_id in remaining_ids and action.get("kind", "").startswith("evidence"):
                evidence_by_id.setdefault(xss_id, []).append(action)
            else:
                if stateful_only and action.get("href"):
                    continue
                generic_actions.append(action)

        selected: list[dict[str, Any]] = []
        while len(selected) < self.max_actions_per_page:
            added = False
            for xss_id in list(evidence_by_id):
                bucket = evidence_by_id[xss_id]
                if not bucket:
                    continue
                selected.append(bucket.pop(0))
                added = True
                if len(selected) >= self.max_actions_per_page:
                    break
            if not added:
                break

        remaining_slots = self.max_actions_per_page - len(selected)
        if remaining_slots > 0:
            generic_actions.sort(key=self._action_priority, reverse=True)
            selected.extend(generic_actions[:remaining_slots])
        return selected

    def _document_url(self, url: str) -> str:
        parsed = urlparse(url or "")
        if not parsed.scheme or not parsed.netloc:
            return url or ""
        return parsed._replace(fragment="").geturl()

    async def _goto(self, page, url: str) -> bool:
        loaded = False
        try:
            # Playwright treats same-document hash changes as light navigations.
            # Some SPAs only initialize the requested hash route on a full document
            # load, so force one when moving between hash routes in the same file.
            current_doc = self._document_url(page.url)
            target_doc = self._document_url(url)
            if (
                current_doc
                and target_doc
                and current_doc == target_doc
                and self._normalize_url(page.url) != self._normalize_url(url)
                and urlparse(url).fragment
            ):
                await page.goto("about:blank", wait_until="domcontentloaded", timeout=5000)
            await page.goto(url, wait_until="domcontentloaded", timeout=10000)
            try:
                await page.wait_for_load_state("networkidle", timeout=3500)
            except PlaywrightTimeoutError:
                pass
            await page.wait_for_timeout(self.settle_ms)
            loaded = True
        except Exception as exc:
            # A response truncated mid-render (a server-side template error, say) never
            # fires DOMContentLoaded, so the load times out -- but the payload was
            # already parsed and its onerror already ran.
            logger.warning("XSS Walker: incomplete load %s: %s", url, exc)
        finally:
            # Those alerts are queued in window.__voapiAlerts. Collect them on both
            # paths, otherwise a failed load silently discards confirmed findings.
            try:
                await self._drain_captured_alerts(page)
            except Exception as exc:
                logger.debug("XSS Walker: alert drain failed on %s: %s", url, exc)
        return loaded

    async def _probe(self, page) -> dict[str, Any]:
        started = perf_counter()
        try:
            frames = list(getattr(page, "frames", [page]))
            ids = self._remaining_ids()
            reports = await asyncio.gather(
                *(frame.evaluate(_DOM_PROBE_JS, ids) for frame in frames),
                return_exceptions=True,
            )
            merged: dict[str, Any] = {
                "url": page.url, "title": "", "actions": [], "links": [], "evidence": [],
            }
            found: set[str] = set()
            hashes = []
            for frame, report in zip(frames, reports):
                if not isinstance(report, dict):
                    continue  # A detached frame must not discard other frames' evidence.
                frame_key = str(id(frame))
                hashes.append((frame_key, report.get("contentHash", "")))
                found.update(report.get("idsFound", []))
                if not merged["title"]:
                    merged["title"] = report.get("title", "")
                for key in ("actions", "links", "evidence"):
                    for item in report.get(key, []):
                        item = dict(item, frameKey=frame_key, frameUrl=frame.url)
                        if key == "actions":
                            item["_frame"] = frame
                        merged[key].append(item)
            if not hashes:
                raise RuntimeError("No frame could be probed")
            merged["idsFound"] = sorted(found)
            merged["contentHash"] = hashlib.md5(json.dumps(hashes).encode()).hexdigest()
            self.probed_urls.add(self._normalize_url(page.url))
            return merged
        finally:
            self.probe_count += 1
            self.probe_ms += (perf_counter() - started) * 1000

    async def _click_action(self, page, action: dict[str, Any]) -> bool:
        if not self._allow_action(action):
            return False
        target = action.get("_frame") or page
        selector = action.get("selector") or ""
        if selector and hasattr(target, "locator"):
            try:
                locator = target.locator(selector)
                double_click = self._should_double_click(action)
                before_url = target.url
                before_state = await target.evaluate(
                    "() => document.body ? document.body.innerHTML : ''"
                ) if double_click else None
                await locator.click(timeout=1500)
                if double_click:
                    await page.wait_for_timeout(120)
                    if target.url == before_url and before_state == await target.evaluate(
                        "() => document.body ? document.body.innerHTML : ''"
                    ):
                        await locator.dblclick(timeout=1500)
                return True
            except Exception as exc:
                logger.debug("XSS Walker: locator action failed for %s: %s", selector, exc)
                return False

        # Coordinate-only actions are retained for legacy callers. Never fall back
        # to stale coordinates after a DOM locator fails.
        point = await self._resolve_click_point(page, action)
        if point is None:
            return False
        x, y = point
        before_url = page.url
        await page.wait_for_timeout(100)
        await page.mouse.click(x, y)
        if self._should_double_click(action):
            # List/tree/menu items -- a DB connection row, a file entry -- often open only
            # on double-click. If the single click did not navigate, follow it with one so
            # the crawler can reach the view (and its render sinks) behind that item.
            await page.wait_for_timeout(120)
            try:
                navigated = page.url != before_url
            except Exception:
                navigated = False
            if not navigated:
                await page.mouse.dblclick(x, y)
        return True

    def _should_double_click(self, action: dict[str, Any]) -> bool:
        """Double-click follow-up is for generic list/tree/menu items, never real
        controls (a <button>/<input>/<a> acts on a single click, so a second would just
        re-invoke it) and never a destructive one."""
        tag = (action.get("tag") or "").upper()
        if tag in {"BUTTON", "INPUT", "A", "SUMMARY", "SELECT", "TEXTAREA", "LABEL", "OPTION"}:
            return False
        return not self._is_dangerous_action(action)

    async def _resolve_click_point(self, page, action: dict[str, Any]):
        selector = action.get("selector") or ""
        if selector:
            try:
                point = await page.evaluate(
                    """
                    (selector) => {
                      const el = document.querySelector(selector);
                      if (!el) return null;
                      if (el.disabled ||
                          el.getAttribute("aria-disabled") === "true" ||
                          el.classList.contains("disabled") ||
                          el.closest("[disabled]")) {
                        return null;
                      }
                      el.scrollIntoView({block: "center", inline: "center"});
                      const rect = el.getBoundingClientRect();
                      const width = window.innerWidth || document.documentElement.clientWidth;
                      const height = window.innerHeight || document.documentElement.clientHeight;
                      if (rect.width < 1 || rect.height < 1) return null;
                      return {
                        x: Math.min(Math.max(rect.left + rect.width / 2, 1), width - 1),
                        y: Math.min(Math.max(rect.top + Math.min(rect.height / 2, 30), 1), height - 1)
                      };
                    }
                    """,
                    selector,
                )
                if point:
                    return float(point["x"]), float(point["y"])
            except Exception as exc:
                logger.debug("XSS Walker: selector click failed: %s", exc)
            return None

        x = action.get("x")
        y = action.get("y")
        if x is None or y is None:
            return None
        return float(x), float(y)

    async def _drain_captured_alerts(self, page) -> int:
        recorded = 0
        for frame in list(getattr(page, "frames", [page])):
            try:
                messages = await frame.evaluate(
                    "() => {"
                    "const messages = window.__voapiAlerts || [];"
                    "window.__voapiAlerts = [];"
                    "return messages;"
                    "}"
                )
            except Exception:
                continue
            for msg in messages or []:
                if self._capture_alert({"page": page, "frame": frame}, msg):
                    recorded += 1
        return recorded

    def _capture_alert(self, source, event) -> bool:
        if not isinstance(event, dict):
            event = {"message": str(event)}
        page = source["page"]
        frame = source.get("frame") or page
        return self._record_alert(
            str(event.get("message", "")), str(event.get("url") or frame.url),
            top_url=str(event.get("topUrl") or page.url),
            kind=str(event.get("kind") or "alert"),
        )

    def _sweep_candidates(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        """The controls to comprehensively interact with on one state: every clickable
        (non-link) control, one per selector, minus destructive ones. Links are excluded --
        BFS already follows them; a control with no selector is excluded -- it cannot be
        re-clicked after a state reload."""
        seen: set[tuple] = set()
        candidates: list[dict[str, Any]] = []
        for action in report.get("actions", []) or []:
            if action.get("href") or (action.get("kind") != "button" and not action.get("interactive")):
                continue
            selector = action.get("selector") or ""
            key = (action.get("frameKey", ""), selector)
            if not selector or key in seen:
                continue
            if not self._allow_action(action):
                continue
            seen.add(key)
            candidates.append(action)
        return candidates

    def _sweep_key(self, action: dict[str, Any]) -> tuple:
        """A control's identity that survives a re-render, unlike its nth-of-type selector:
        its label plus its coarse on-screen position. Co-located wrappers (a div and its inner
        <i>) collapse to one; same-labelled controls elsewhere stay distinct."""
        x = action.get("x") or 0
        y = action.get("y") or 0
        return (action.get("frameKey", ""), action.get("text", ""), round(x / 25), round(y / 25))

    _OVERLAY_JS = r"""
    () => {
      const sel = '.ant-modal-wrap, .ant-drawer.ant-drawer-open, .ant-modal-mask, [role=dialog]';
      for (const el of document.querySelectorAll(sel)) {
        const r = el.getBoundingClientRect();
        const st = window.getComputedStyle(el);
        if (r.width > 0 && r.height > 0 && st.display !== 'none' && st.visibility !== 'hidden') {
          return true;
        }
      }
      return false;
    }
    """

    async def _has_blocking_overlay(self, page) -> bool:
        """A modal/drawer still covering the page (e.g. one Escape could not dismiss)."""
        try:
            return bool(await page.evaluate(self._OVERLAY_JS))
        except Exception:
            return False

    async def _dismiss_overlays(self, page) -> None:
        """Close a modal/drawer/dropdown a click just opened so the next control starts clean --
        the cheap alternative to a full reload. Most overlays close on Escape (Ant Design and the
        like); one that ignores it is caught by _has_blocking_overlay, which forces a reload."""
        try:
            await page.keyboard.press("Escape")
            await page.wait_for_timeout(120)
            await page.keyboard.press("Escape")  # a second, for a stacked overlay
            await page.wait_for_timeout(120)
        except Exception:
            pass

    async def _comprehensive_sweep(self, page, url: str, report: dict[str, Any]) -> int:
        """Comprehensive user interaction over one UI state. Click every distinct control
        once, draining alerts so an execution sink is caught by its ID.

        The state is re-probed before every click, so a selector is never stale after a prior
        click re-rendered the DOM (opened a panel) or navigated away -- the failure that lets a
        deep panel opener be clicked with a selector pointing at the wrong element. Controls are
        deduped by a render-stable key. After each click the overlay it opened is dismissed with
        Escape (cheap); the state is fully reloaded only when a click navigated away or left a
        modal Escape could not close -- so one interaction never robs the others of their turn."""
        swept: set[tuple] = set()
        clicks = 0
        max_clicks = 60
        while not self._all_triggered() and clicks < max_clicks:
            # Reset to a clean baseline only when needed: a prior click navigated away, or left
            # a modal Escape could not dismiss. Otherwise the previous iteration's Escape already
            # cleaned up, so the slow full reload is skipped.
            if (
                self._normalize_url(page.url) != self._normalize_url(url)
                or await self._has_blocking_overlay(page)
            ):
                if not await self._goto(page, url):
                    break
            try:
                report = await self._probe(page)
            except Exception:
                break
            candidates = [
                action for action in self._sweep_candidates(report)
                if self._sweep_key(action) not in swept
            ]
            if not candidates:
                break
            action = candidates[0]
            swept.add(self._sweep_key(action))
            clicks += 1
            logger.debug(
                "XSS Walker: sweep click %d text=%r tag=%s",
                clicks, (action.get("text") or "")[:16], action.get("tag"),
            )
            try:
                if not await self._click_action(page, action):
                    continue
                # A panel opener mounts its view and fetches before it renders (and fires);
                # wait for that, but not the full page-load settle -- the state is already up.
                await page.wait_for_timeout(2500)
                await self._drain_captured_alerts(page)
                await self._dismiss_overlays(page)
            except Exception as exc:
                logger.debug(
                    "XSS Walker: sweep click failed on %s: %s",
                    action.get("selector"), exc,
                )
        return clicks

    def _visible_unconfirmed(self, report: dict[str, Any]) -> set[str]:
        """Registered payloads that appear on this state's DOM but are not yet confirmed."""
        remaining = set(self._remaining_ids())
        visible = set(report.get("idsFound", []) or [])
        for item in report.get("evidence", []) or []:
            xss_id = item.get("id") or ""
            if xss_id:
                visible.add(xss_id)
        return visible & remaining

    def _note_sweep_state(self, page, report: dict[str, Any]) -> None:
        """Record a state where a still-unconfirmed payload is visible, for a deferred sweep.
        We do NOT sweep inline: the reload-per-click sweep is slow, and doing it during the
        crawl would starve the walker from reaching a page where the payload renders (fires) on
        load -- which is how most stored XSS confirm. The sweep is a fallback for the rest."""
        if self.button_crawl_mode == "off":
            return
        normalized = self._normalize_url(page.url)
        if normalized in self.swept_states or normalized in self.sweep_pending:
            return
        if self._visible_unconfirmed(report):
            self.sweep_pending[normalized] = page.url

    async def _run_deferred_sweeps(self, page) -> None:
        """After the crawl, comprehensively sweep the recorded states that still hold an
        unconfirmed visible payload -- the client-side-sink cases a page load did not fire."""
        for normalized, url in list(self.sweep_pending.items()):
            if self._all_triggered():
                break
            if normalized in self.swept_states:
                continue
            if not await self._goto(page, url):
                continue
            try:
                report = await self._probe(page)
            except Exception:
                continue
            if not self._visible_unconfirmed(report):
                continue  # a later crawl page already confirmed it
            self.swept_states.add(normalized)
            logger.info("XSS Walker: deferred comprehensive sweep on %s", url)
            await self._comprehensive_sweep(page, url, report)

    def _reserve_url(self, url: str) -> str | None:
        resolved = self._resolve_url(url)
        normalized = self._normalize_url(resolved)
        if not self._same_origin(resolved):
            return None
        if normalized in self.visited_urls or normalized in self.queued_urls:
            return None
        self.queued_urls.add(normalized)
        return resolved

    def _enqueue_url(self, frontier: deque[str], url: str, priority: bool = False) -> None:
        resolved = self._reserve_url(url)
        if resolved is None:
            return
        if priority:
            frontier.appendleft(resolved)
        else:
            frontier.append(resolved)

    def _ranked_link_scores(self, report: dict[str, Any]) -> list[tuple[str, int]]:
        best_scores: dict[str, int] = {}
        remaining = set(self._remaining_ids())
        for item in report.get("evidence", []):
            href = item.get("href") or ""
            link = item.get("link") or {"href": href, "text": item.get("text", "")}
            if not href or not self._allow_action(link, navigation=True):
                continue
            score = self._priority_score(href, item.get("text", ""), item.get("id", ""))
            if item.get("id") in remaining:
                score += 500
            best_scores[href] = max(best_scores.get(href, -10_000), score)
        for action in report.get("links", []) + report.get("actions", []):
            href = action.get("href") or ""
            if not href or not self._allow_action(action, navigation=True):
                continue
            score = self._priority_score(href, action.get("text", ""), action.get("xssId", ""))
            if action.get("xssId") in remaining:
                score += 500
            best_scores[href] = max(best_scores.get(href, -10_000), score)
        return sorted(best_scores.items(), key=lambda item: item[1])

    def _enqueue_links(self, report: dict[str, Any], frontier: deque[str]) -> None:
        for href, score in self._ranked_link_scores(report):
            self._enqueue_url(frontier, href, priority=score > 0)

    def _enqueue_stateful_click_page(
        self,
        report: dict[str, Any],
        page_url: str | None = None,
        *,
        include_visible: bool = False,
    ) -> None:
        if self.max_stateful_pages <= 0 or self.button_crawl_mode == "off":
            return
        if not any(
            self._allow_action(action) and not action.get("href") and (
                self._should_revisit_page_for_action(action)
                or (include_visible and self._action_allowed_by_viewport(action))
            )
            for action in report.get("actions", [])
        ):
            return
        url = report.get("url") or page_url or ""
        normalized = self._normalize_url(url)
        if not self._same_origin(url):
            return
        if (
            normalized in self.queued_stateful_click_urls
            or normalized in self.explored_stateful_click_urls
        ):
            return
        self.queued_stateful_click_urls.add(normalized)
        self.stateful_click_urls.append(url)

    def _process_report(self, page, report, frontier=None, *, url_only=False) -> None:
        """URL discovery and interaction completion are separate pieces of work."""
        self._remember_report_ids(report)
        self._log_evidence(report)
        self._note_sweep_state(page, report)
        if frontier is not None:
            self._enqueue_links(report, frontier)
        self._enqueue_stateful_click_page(report, page.url, include_visible=url_only)

    def _log_evidence(self, report: dict[str, Any]) -> None:
        evidence = report.get("evidence", [])
        if not evidence:
            return
        contexts: dict[str, int] = {}
        for item in evidence:
            context = item.get("context", "unknown")
            contexts[context] = contexts.get(context, 0) + 1
        logger.info(
            "XSS Walker: IDs visible on %s contexts=%s",
            report.get("url"),
            contexts,
        )

    def _initial_frontier(self) -> deque[str]:
        frontier: deque[str] = deque()
        self.queued_urls = set()
        self._enqueue_url(frontier, self.home_url)
        for seed_url in self.seed_urls:
            self._enqueue_url(frontier, seed_url)
        return frontier

    async def _new_context(self, browser):
        context = await browser.new_context()
        await context.expose_binding("__voapiReportAlert", self._capture_alert)
        await context.add_init_script(script=_ALERT_HOOK_JS)
        context.on("page", self._attach_page_handlers)
        cookies = parse_cookie_str(self.cookie_str, self.domain)
        if cookies:
            await context.add_cookies(cookies)
        if self.local_storage:
            storage_json = json.dumps(self.local_storage)
            await context.add_init_script(
                script=(
                    "(() => {"
                    f"const values = {storage_json};"
                    "for (const [key, value] of Object.entries(values)) {"
                    "localStorage.setItem(key, value);"
                    "}"
                    "})();"
                )
            )
        return context

    def _attach_page_handlers(self, page) -> None:
        if page in self._attached_pages:
            return
        self._attached_pages.add(page)
        page.on("dialog", self.handle_dialog)

    async def _run_parallel_url_phase(self, context, frontier: deque[str]) -> int:
        budget = min(self.parallel_url_budget, self.max_steps)
        if self.parallel_url_workers <= 1 or budget <= 0 or not frontier or self._all_triggered():
            return 0

        queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        sequence = count()
        while frontier:
            url = frontier.popleft()
            queue.put_nowait((-self._priority_score(url), next(sequence), url))

        visited_in_phase = 0
        leftover: list[tuple[int, int, str]] = []
        self._confirmation_event = asyncio.Event()

        def enqueue_from_report(report, page_url):
            candidates = self._ranked_link_scores(report) + [(page_url, self._priority_score(page_url))]
            for candidate, score in candidates:
                resolved = self._reserve_url(candidate)
                if resolved is not None:
                    queue.put_nowait((-score, next(sequence), resolved))

        async def worker():
            nonlocal visited_in_phase
            page = None
            try:
                page = await context.new_page()
                self._attach_page_handlers(page)
                while True:
                    entry = await queue.get()
                    try:
                        _priority, _sequence, target = entry
                        if visited_in_phase >= budget or self._all_triggered():
                            leftover.append(entry)
                            continue
                        normalized = self._normalize_url(target)
                        if normalized in self.visited_urls or not self._same_origin(target):
                            continue
                        # No await between checking and reserving: atomic on this event loop.
                        self.visited_urls.add(normalized)
                        visited_in_phase += 1
                        self._active_url_workers += 1
                        self.peak_active_url_workers = max(self.peak_active_url_workers, self._active_url_workers)
                        try:
                            if await self._goto(page, target):
                                report = await self._probe(page)
                                self._process_report(page, report, url_only=True)
                                # Publish discoveries before marking the parent task done.
                                enqueue_from_report(report, page.url)
                            else:
                                self.unreachable_url_count += 1
                        except Exception as exc:
                            self.unreachable_url_count += 1
                            logger.debug("XSS Walker: parallel visit failed on %s: %s", target, exc)
                        finally:
                            self._active_url_workers -= 1
                    finally:
                        queue.task_done()
            finally:
                if page is not None:
                    try:
                        await self._drain_captured_alerts(page)
                    finally:
                        await page.close()

        workers = [asyncio.create_task(worker()) for _ in range(self.parallel_url_workers)]
        joined = asyncio.create_task(queue.join())
        confirmed = asyncio.create_task(self._confirmation_event.wait())
        tasks = workers + [joined, confirmed]
        try:
            # Workers wait for more work while another worker is discovering links.
            # Monitor worker failure too, so a failed new_page cannot strand queue.join.
            done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in tasks:
                task.cancel()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, Exception):
                    logger.debug("XSS Walker: worker shutdown: %s", result)
            self._confirmation_event = None
            while not queue.empty():
                leftover.append(queue.get_nowait())
                queue.task_done()
            for _priority, _sequence, url in sorted(leftover):
                if self._normalize_url(url) not in self.visited_urls:
                    frontier.append(url)

        logger.info(
            "XSS Walker: parallel phase visited=%d pending=%d peak_workers=%d",
            visited_in_phase, len(frontier), self.peak_active_url_workers,
        )
        return visited_in_phase

    async def run(self):
        self.stop_reason = "running"
        if not len(self.xss_registry):
            self.stop_reason = "no_registered_ids"
            return self.triggered_ids
        logger.info(
            (
                "XSS Walker starting: home=%s, registered IDs=%d, max_steps=%d, "
                "parallel_url_workers=%d, parallel_url_budget=%d"
            ),
            self.home_url,
            len(self.xss_registry),
            self.max_steps,
            self.parallel_url_workers,
            self.parallel_url_budget,
        )
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            frontier = self._initial_frontier()
            try:
                context = await self._new_context(browser)
                page = await context.new_page()
                self._attach_page_handlers(page)
                await self._run_parallel_url_phase(context, frontier)
                step_count = len(self.visited_urls)
                while (
                    (self.stateful_click_urls and (
                        len(self.explored_stateful_click_urls) < self.max_stateful_pages
                    ))
                    or (frontier and step_count < self.max_steps)
                ) and not self._all_triggered():
                    stateful_revisit = False
                    if (
                        self.stateful_click_urls
                        and len(self.explored_stateful_click_urls) < self.max_stateful_pages
                    ):
                        current_target = self.stateful_click_urls.popleft()
                        stateful_revisit = True
                    else:
                        current_target = frontier.popleft()
                    normalized_target = self._normalize_url(current_target)
                    if stateful_revisit:
                        if normalized_target in self.explored_stateful_click_urls:
                            continue
                        self.explored_stateful_click_urls.add(normalized_target)
                        if normalized_target not in self.visited_urls:
                            self.visited_urls.add(normalized_target)
                            step_count += 1
                    elif normalized_target in self.visited_urls:
                        continue
                    if not self._same_origin(current_target):
                        continue
                    if not stateful_revisit:
                        self.visited_urls.add(normalized_target)
                        step_count += 1

                    if not await self._goto(page, current_target):
                        self.unreachable_url_count += 1
                        continue

                    page_action_count = 0
                    noop_click_count = 0
                    while page_action_count < max(1, self.max_actions_per_page):
                        try:
                            await self._drain_captured_alerts(page)
                            report = await self._probe(page)
                        except Exception as exc:
                            logger.debug("XSS Walker: probe failed on %s: %s", page.url, exc)
                            break
                        pre_click_report_signature = self._report_signature(report)
                        self._process_report(page, report, frontier)
                        logger.debug(
                            "XSS Walker: page=%s ids=%s actions=%d",
                            report.get("url"),
                            report.get("idsFound", []),
                            len(report.get("actions", [])),
                        )
                        if page_action_count >= self.max_actions_per_page or self._all_triggered():
                            break

                        selected_action = None
                        selected_signature = None
                        for action in self._select_actions(
                            report.get("actions", []),
                            stateful_only=stateful_revisit,
                            page_url=report.get("url", page.url),
                            page_state=pre_click_report_signature,
                        ):
                            if self._action_mentions_triggered_id(action):
                                continue
                            signature = self._action_signature(
                                report.get("url", page.url),
                                action,
                                pre_click_report_signature,
                            )
                            if signature in self.clicked_actions:
                                continue
                            selected_action = action
                            selected_signature = signature
                            break

                        if selected_action is None or selected_signature is None:
                            break

                        action = selected_action
                        self.clicked_actions.add(selected_signature)
                        page_action_count += 1
                        triggered_before = len(self.triggered_ids)

                        if self._normalize_url(page.url) != self._normalize_url(report.get("url", "")):
                            if not await self._goto(page, report.get("url", current_target)):
                                break
                        logger.debug(
                            "XSS Walker: click kind=%s text=%r href=%s page=%s",
                            action.get("kind"),
                            action.get("text"),
                            action.get("href"),
                            report.get("url"),
                        )
                        try:
                            if not await self._click_action(page, action):
                                continue
                            await page.wait_for_timeout(max(500, self.settle_ms))
                            try:
                                await page.wait_for_load_state("networkidle", timeout=1500)
                            except PlaywrightTimeoutError:
                                pass
                            await self._drain_captured_alerts(page)
                        except Exception as exc:
                            logger.debug("XSS Walker: click failed: %s", exc)
                            continue

                        try:
                            await self._drain_captured_alerts(page)
                            local_report = await self._probe(page)
                            post_click_report_signature = self._report_signature(local_report)
                            self._process_report(page, local_report, frontier)
                        except Exception:
                            local_report = {}
                            post_click_report_signature = ""

                        url_changed = False
                        if self._same_origin(page.url):
                            normalized = self._normalize_url(page.url)
                            if normalized != normalized_target:
                                url_changed = True
                                if stateful_revisit:
                                    if normalized not in self.visited_urls:
                                        self.visited_urls.add(normalized)
                                    current_target = page.url
                                    normalized_target = normalized
                                else:
                                    self._enqueue_url(frontier, page.url, priority=True)
                                    if not await self._goto(page, current_target):
                                        break
                            elif (
                                normalized not in self.visited_urls
                                and normalized not in self.queued_urls
                            ):
                                frontier.append(page.url)
                                self.queued_urls.add(normalized)

                        new_trigger = len(self.triggered_ids) > triggered_before
                        if (
                            not url_changed
                            and not new_trigger
                            and post_click_report_signature
                            and post_click_report_signature == pre_click_report_signature
                        ):
                            noop_click_count += 1
                            if noop_click_count >= self.max_noop_clicks_per_page:
                                logger.debug(
                                    "XSS Walker: stopping page after %d no-op clicks on %s",
                                    noop_click_count,
                                    report.get("url"),
                                )
                                break
                        else:
                            noop_click_count = 0

                        if self._all_triggered():
                            break

                    if self._all_triggered():
                        break

                # Crawl finished. Now sweep the states that still hold an unconfirmed visible
                # payload -- the client-side-sink cases where a page load never fired one.
                if not self._all_triggered():
                    await self._run_deferred_sweeps(page)
                self.stop_reason = (
                    "all_confirmed" if self._all_triggered() else
                    "url_budget" if frontier and step_count >= self.max_steps else
                    "interaction_budget" if self.stateful_click_urls else "frontier_exhausted"
                )

            except asyncio.CancelledError:
                self.stop_reason = "cancelled"
                raise
            except Exception as e:
                self.stop_reason = "error"
                logger.error("XSS Walker error: %s", e)
            finally:
                summary = self.summary()
                logger.info(
                    (
                        "XSS Walker finished: pages=%d clicked=%d confirmed=%d "
                        "observed_unconfirmed=%d not_observed=%d"
                    ),
                    summary["visited_count"],
                    summary["clicked_count"],
                    summary["confirmed"],
                    summary["observed_unconfirmed"],
                    summary["not_observed"],
                )
                await browser.close()

        return self.triggered_ids
