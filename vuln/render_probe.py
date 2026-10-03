"""Confirm stored XSS that renders through a client-side HTML sink.

Some payloads execute only when the frontend renders a stored field via innerHTML /
dangerouslySetInnerHTML / v-html, inside a view the crawler cannot reach (a panel behind
SPA navigation). Rather than drive that UI, reproduce the render directly: in the app's own
origin (so the session cookie is present and same-origin fetches are authorized), fetch the
resource's read endpoint and innerHTML every reflected string field -- exactly what the
vulnerable component does. If the injected payload's alert fires, it is confirmed.

This never false-fires on server-encoded storage: innerHTML of encoded text (``&lt;img..``)
is inert. It does assume the frontend renders the field via an HTML sink; pair it with a
source check for that sink to rule out fields that are only ever shown as text.
"""

from __future__ import annotations

import json
import logging

from vuln.recorder import VulnRecorder
from vuln.xss_registry import XSSRegistry
from vuln.xss_walker import _ALERT_HOOK_JS, parse_cookie_str

logger = logging.getLogger(__name__)

# Fetch each read endpoint same-origin and render every reflected string field the way the
# frontend does (innerHTML == React dangerouslySetInnerHTML / Vue v-html). Alerts fired by a
# payload's onerror are captured by _ALERT_HOOK_JS into window.__voapiAlerts.
_RENDER_JS = r"""
async (readUrls) => {
  for (const url of readUrls) {
    try {
      const resp = await fetch(url, { credentials: 'include' });
      const data = await resp.json();
      const stack = [data];
      const strings = [];
      while (stack.length) {
        const node = stack.pop();
        if (node && typeof node === 'object') {
          for (const v of Object.values(node)) {
            if (typeof v === 'string') strings.push(v);
            else if (v && typeof v === 'object') stack.push(v);
          }
        }
      }
      for (const s of strings) {
        const d = document.createElement('div');
        d.innerHTML = s;
        document.body.appendChild(d);
      }
    } catch (e) { /* a read that fails to fetch/parse just yields no strings */ }
  }
  await new Promise((r) => setTimeout(r, 800));
  const hits = window.__voapiAlerts || [];
  window.__voapiAlerts = [];
  return hits;
}
"""


class RenderProbe:
    def __init__(
        self,
        home_url: str,
        cookie_str: str,
        domain: str,
        xss_registry: XSSRegistry,
        vuln_recorder: VulnRecorder,
        local_storage: dict[str, str] | None = None,
        headless: bool = True,
    ):
        self.home_url = home_url
        self.cookie_str = cookie_str
        self.domain = domain
        self.xss_registry = xss_registry
        self.vuln_recorder = vuln_recorder
        self.local_storage = local_storage or {}
        self.headless = headless
        self.triggered_ids: list[str] = []

    async def run(self, read_urls: list[str]) -> list[str]:
        if not read_urls:
            return []
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context()
            await context.add_init_script(script=_ALERT_HOOK_JS)
            cookies = parse_cookie_str(self.cookie_str, self.domain)
            if cookies:
                await context.add_cookies(cookies)
            if self.local_storage:
                storage_json = json.dumps(self.local_storage)
                await context.add_init_script(
                    "(() => { const s = "
                    + storage_json
                    + "; for (const k in s) localStorage.setItem(k, s[k]); })();"
                )
            page = await context.new_page()
            try:
                await page.goto(
                    self.home_url, wait_until="domcontentloaded", timeout=20000
                )
            except Exception as exc:
                logger.warning("RenderProbe: home load failed %s: %s", self.home_url, exc)
            try:
                hits = await page.evaluate(_RENDER_JS, read_urls)
            except Exception as exc:
                logger.warning("RenderProbe: render failed: %s", exc)
                hits = []
            for hit in hits:
                self.record_alert(hit.get("message", "") if isinstance(hit, dict) else str(hit))
            await browser.close()
        return self.triggered_ids

    def record_alert(self, message: str) -> bool:
        """Write walker-compatible evidence when an alert carries a registered XSS id."""
        xss_id = self.xss_registry.find_id_in_text(message)
        if not xss_id or xss_id in self.triggered_ids:
            return False
        record = self.xss_registry.lookup(xss_id)
        if record is None:
            return False
        self.triggered_ids.append(xss_id)
        logger.info(
            "XSS confirmed via render-probe! ID=%s url=%s param=%s",
            xss_id, record.api_url, record.param_name,
        )
        vuln_dir = self.vuln_recorder.root / "xss"
        vuln_dir.mkdir(parents=True, exist_ok=True)
        content = (
            "API Vul Type: XSS\n"
            f"Vul API Url: {record.api_url}\n"
            f"Vul API Method: {record.api_method}\n"
            f"API Vul Param: {record.param_name}\n"
            f"API Test Payload: {record.attack_payload}\n"
            f"XSS ID: {xss_id}\n"
            "Confirmed By: render-probe (innerHTML of read-endpoint reflection)\n"
            f"Alert Message: {message}\n"
        )
        safe_url = record.api_url.replace("/", "!")
        (vuln_dir / f"{safe_url}!{record.param_name}.txt").open("a").write(content + "\n")
        return True
