import logging
import random
import string
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from faker import Faker

from models.api_model import APIModel
from runtime.materializers.request import RequestMaterializer, RequestPayload


logger = logging.getLogger(__name__)


class PayloadGenerator(Protocol):
    def generate(self, api_model: APIModel) -> RequestPayload:
        ...


@dataclass
class RuleBasedPayloadGenerator:
    materializer: RequestMaterializer

    def generate(self, api_model: APIModel) -> RequestPayload:
        return self.materializer.materialize(api_model)


class DependencyManager:
    def __init__(self) -> None:
        self._values: dict[str, list[Any]] = {}

    def __call__(self, tag: str, default: Any = None) -> Any:
        return self.get(tag, default)

    def get(self, tag: str, default: Any = None) -> Any:
        values = self._values.get(tag)
        if not values:
            return default
        return values[-1]

    def set(self, tag: str, value: Any) -> None:
        if tag is None:
            return
        if value is None:
            return
        if isinstance(value, str) and not value.strip():
            return
        if isinstance(value, (list, dict)) and not value:
            return
        self._values.setdefault(tag, []).append(value)


def _unknown_attr(facade: str, name: str, hint: str) -> AttributeError:
    """Build an error the LLM can act on.

    Generated snippets reach for helpers that sound plausible but do not exist
    (``ctx.random.hex`` cost one Jellyfin run 17 aborted payloads). The failure
    text is fed straight back into the next prompt, so naming the real helper
    here is what lets the model correct itself instead of guessing again.
    """
    return AttributeError(f"ctx.{facade} has no '{name}'. {hint}")


class FakerFacade:
    def __init__(self, fake: Faker) -> None:
        self._fake = fake

    def __getattr__(self, name: str) -> Any:
        try:
            return getattr(self._fake, name)
        except AttributeError:
            raise _unknown_attr(
                "fake",
                name,
                "Use a real Faker provider (fake.name(), fake.email(), fake.uuid4(), "
                "fake.url(), fake.word(), fake.pystr()) or fake.hexify(n) for hex digits.",
            ) from None

    def hexify(self, text: Any = "^^^^", upper: bool = False) -> str:
        if isinstance(text, int):
            text = "^" * max(0, text)
        return self._fake.hexify(text=text, upper=upper)


class RandomFacade:
    def __init__(self, module: Any = random) -> None:
        self._module = module

    def __getattr__(self, name: str) -> Any:
        try:
            return getattr(self._module, name)
        except AttributeError:
            raise _unknown_attr(
                "random",
                name,
                "Available: random.string(length, alphabet=None) for a random token, "
                "random.hexstring(length) for hex digits, plus the stdlib random module "
                "(randint, choice, choices, sample, uniform, shuffle).",
            ) from None

    def string(self, length: int = 8, alphabet: Optional[str] = None) -> str:
        try:
            size = int(length)
        except Exception:
            size = 8
        chars = alphabet or (string.ascii_letters + string.digits)
        return "".join(self._module.choice(chars) for _ in range(max(0, size)))

    def hexstring(self, length: int = 8) -> str:
        """Random hex digits.

        The models kept reaching for a hex helper on ``ctx.random`` and inventing
        a name for it; giving them one costs nothing and removes the guess.
        """
        return self.string(length, alphabet=string.hexdigits[:16])


@dataclass
class GenerationContext:
    dep: DependencyManager
    fake: Any
    random: Any

    def __init__(
        self,
        dep: Optional[DependencyManager] = None,
        fake: Optional[Faker] = None,
    ):
        self.dep = dep or DependencyManager()
        self.fake = FakerFacade(fake or Faker())
        self.random = RandomFacade(random)


@dataclass
class CodeBasedPayloadGenerator:
    dep_manager: Optional[DependencyManager] = None
    header_default: Optional[dict[str, Any]] = None
    fake: Faker = field(init=False)

    def __post_init__(self) -> None:
        self.fake = Faker()

    def _empty_payload(self) -> RequestPayload:
        header = self.header_default or {}
        return RequestPayload(path={}, header=header, query={}, body={})

    def generate(self, api_model: APIModel) -> RequestPayload:
        code = api_model.payload_factory_code
        if not code:
            raise ValueError("payload_factory_code is missing on APIModel")

        context = GenerationContext(self.dep_manager, self.fake)
        wrapped_code = (
            "def make_payload(ctx):\n"
            + "\n".join("    " + line for line in code.splitlines())
            + "\nresult = make_payload(ctx)"
        )

        local_scope: dict[str, Any] = {"ctx": context, "result": None}
        try:
            exec(wrapped_code, {}, local_scope)
        except Exception as exc:
            logger.exception("Failed to execute payload_factory_code: %s", exc)
            return self._empty_payload()

        result = local_scope.get("result")
        if not isinstance(result, dict):
            logger.warning("payload_factory_code did not return a dict")
            return self._empty_payload()

        path = result.get("path", {})
        query = result.get("query", {})
        body = result.get("body", {})
        header = result.get("header", {})
        if not isinstance(path, dict):
            path = {}
        if not isinstance(query, dict):
            query = {}
        if not isinstance(header, dict):
            header = {}
        if not isinstance(body, (dict, list)):
            body = {}
        if self.header_default:
            header = {**self.header_default, **header}
        return RequestPayload(path=path, header=header, query=query, body=body)
