"""
agent_model.py - the optional language model behind `rasd advise`.

The counsel is computed from the repository and never needs a model. A model, when one is
configured, adds what computation cannot: a narrative for an analyst, a first draft of a rule
edit or of a new rule for an engineer, an answer to a free question. Everything a model writes
passes the same gates as a person's work before it is kept - the engine, the tests, the proofs -
and the gates decide, not the model. Without a model every command of `rasd advise` still runs;
the parts a model would add are simply absent.

Configuration, from environment variables only (nothing is read from files):

  RASD_MODEL           the model name; unset means no model
  RASD_MODEL_URL       the server. Either a server that speaks the chat-completions API
                       (POST <url>/chat/completions, the form most hosted and self-hosted
                       servers accept) or a local Ollama (http://localhost:11434)
  RASD_MODEL_KEY       bearer token, when the server needs one
  RASD_MODEL_PROVIDER  chat | ollama (default: ollama for a URL on port 11434, else chat)
  RASD_MODEL_TIMEOUT   seconds to wait for an answer (default 120)

Chat-completions servers differ on two request fields, and the client follows what the server
says and remembers it for the calls that follow: one that asks for max_completion_tokens gets
it, and one that refuses a temperature gets none. An answer cut at the token limit is asked for
once more with more room. A server that is busy (429, 5xx) is asked again twice before the
call fails.

What leaves the machine: the prompt holds rule text, test events and counts from the repository,
which are public, and nothing from your own logs unless `--share-events` is passed; a shared
event is redacted first (addresses, host names and account names replaced by placeholders).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

PROVIDERS = ("chat", "ollama")
DEFAULT_TIMEOUT = 120
BUSY = frozenset({429, 500, 502, 503, 504, 529})
WAITS = (3, 12)
REASONING_ROOM = 4


class ModelError(Exception):
    """The model could not be reached, or answered in a form the gate refuses. `status` is the HTTP
    status when the server answered with one."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class Model:
    name: str
    url: str
    provider: str
    key: str | None = None
    timeout: int = DEFAULT_TIMEOUT
    limit: str = field(default="max_tokens", repr=False)
    temperature: bool = field(default=True, repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Model | None:
        env = os.environ if env is None else env
        name = (env.get("RASD_MODEL") or "").strip()
        if not name:
            return None
        url = (env.get("RASD_MODEL_URL") or "").strip().rstrip("/")
        provider = (env.get("RASD_MODEL_PROVIDER") or "").strip().lower()
        if not provider:
            provider = "ollama" if (not url or ":11434" in url) else "chat"
        if provider not in PROVIDERS:
            raise ModelError(f"RASD_MODEL_PROVIDER must be one of {', '.join(PROVIDERS)}, not '{provider}'")
        if not url:
            if provider != "ollama":
                raise ModelError("RASD_MODEL_URL is not set: the chat-completions server to talk to")
            url = "http://localhost:11434"
        if not url.startswith(("http://", "https://")):
            raise ModelError("RASD_MODEL_URL must start with http:// or https://")
        try:
            timeout = int(env.get("RASD_MODEL_TIMEOUT") or DEFAULT_TIMEOUT)
        except ValueError as e:
            raise ModelError("RASD_MODEL_TIMEOUT must be a number of seconds") from e
        return cls(name, url, provider, (env.get("RASD_MODEL_KEY") or "").strip() or None, timeout)

    def describe(self) -> str:
        return f"{self.name} via {self.provider} at {self.url}"

    # ---- transport -------------------------------------------------------
    def _post(self, path: str, body: dict) -> dict:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        data = json.dumps(body).encode("utf-8")
        for wait in (*WAITS, None):
            # the URL is the operator's own setting and from_env admits http and https only
            req = urllib.request.Request(self.url + path, data=data, headers=headers, method="POST")  # noqa: S310
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:   # noqa: S310
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", errors="replace")[:300]
                if e.code in BUSY and wait is not None:
                    time.sleep(wait)
                    continue
                raise ModelError(f"the model server answered {e.code} for {path}: {detail}", e.code) from e
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                raise ModelError(f"the model server at {self.url} could not be reached: {e}") from e
            except json.JSONDecodeError as e:
                raise ModelError(f"the model server at {self.url} did not answer with JSON") from e
        raise ModelError(f"the model server at {self.url} stayed busy")

    def _chat(self, messages: list[dict], max_tokens: int) -> dict:
        """One chat-completions exchange. Servers differ on two fields and say so with a 400: one that asks for
        max_completion_tokens gets it, with room for the reasoning such a server counts there, and one that
        refuses a temperature gets none. What a server accepted is kept for the calls that follow."""
        while True:
            body: dict[str, Any] = {"model": self.name, "messages": messages,
                                    self.limit: max_tokens * (REASONING_ROOM if self.limit == "max_completion_tokens" else 1)}
            if self.temperature:
                body["temperature"] = 0
            try:
                return self._post("/chat/completions", body)
            except ModelError as e:
                if e.status != 400:
                    raise
                if "max_completion_tokens" in str(e) and self.limit == "max_tokens":
                    self.limit = "max_completion_tokens"
                elif "temperature" in str(e) and self.temperature:
                    self.temperature = False
                else:
                    raise

    def complete(self, system: str, user: str, max_tokens: int = 1500) -> str:
        """The model's text for one exchange, at temperature 0 where the server takes one."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        if self.provider == "ollama":
            out = self._post("/api/chat", {"model": self.name, "messages": messages, "stream": False,
                                           "options": {"temperature": 0, "num_predict": max_tokens}})
            text = ((out.get("message") or {}).get("content"))
        else:
            out = self._chat(messages, max_tokens)
            choices = out.get("choices") or []
            if choices and choices[0].get("finish_reason") == "length":
                out = self._chat(messages, max_tokens * REASONING_ROOM)
                choices = out.get("choices") or []
            text = ((choices[0].get("message") or {}).get("content")) if choices else None
        if not isinstance(text, str) or not text.strip():
            raise ModelError("the model answered with no text")
        return text

    def json(self, system: str, user: str, required: Sequence[str], max_tokens: int = 1500) -> dict:
        """The model's answer as one JSON object holding every required key; anything else is refused."""
        text = self.complete(system + "\nAnswer with one JSON object and nothing else.", user, max_tokens)
        doc = extract_json(text)
        missing = [k for k in required if k not in doc]
        if missing:
            raise ModelError(f"the model's answer lacks {', '.join(missing)}")
        return doc


def extract_json(text: str) -> dict:
    """The one JSON object in a model's answer, with or without a code fence around it."""
    body = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", body, re.S)
    if fence:
        body = fence.group(1)
    start, end = body.find("{"), body.rfind("}")
    if start < 0 or end <= start:
        raise ModelError("the model's answer holds no JSON object")
    try:
        doc = json.loads(body[start:end + 1])
    except json.JSONDecodeError as e:
        raise ModelError(f"the model's answer is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise ModelError("the model's answer is not a JSON object")
    return doc


def status(env: Mapping[str, str] | None = None) -> str:
    """One line on whether a model is configured, for the console."""
    try:
        m = Model.from_env(env)
    except ModelError as e:
        return f"model: misconfigured ({e})"
    return f"model: {m.describe()}" if m else "model: none configured (RASD_MODEL unset); computed counsel only"


# --------------------------------------------------------------------------- #
# Redaction: what an event looks like before it is shared with a model
# --------------------------------------------------------------------------- #
HOST_KEYS = {"computer", "computername", "host", "hostname", "workstationname", "src_host", "dst_host", "node_id",
             "ipaddress", "clientaddress", "sourceip", "destinationip", "src_ip", "dst_ip", "remote_addr", "client_ip"}
USER_KEYS = {"user", "username", "subjectusername", "targetusername", "accountname", "logdata.username", "subjectdomainname",
             "targetdomainname", "remote_user"}
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_UNC = re.compile(r"\\\\([A-Za-z0-9][A-Za-z0-9._-]*)")


class Redactor:
    """Replaces addresses, host names and account names with numbered placeholders, consistently
    within one call, so the model sees the shape of an event and not whose it is."""

    def __init__(self) -> None:
        self.seen: dict[tuple[str, str], str] = {}

    def token(self, kind: str, value: str) -> str:
        key = (kind, value.lower())
        if key not in self.seen:
            self.seen[key] = f"<{kind}-{len([k for k in self.seen if k[0] == kind]) + 1}>"
        return self.seen[key]

    def text(self, value: str) -> str:
        def ip(m: re.Match) -> str:
            try:
                ipaddress.ip_address(m.group(0))
            except ValueError:
                return m.group(0)
            return self.token("ip", m.group(0))
        value = _IPV4.sub(ip, value)
        return _UNC.sub(lambda m: "\\\\" + self.token("host", m.group(1)), value)

    def event(self, obj: Any, key: str = "") -> Any:
        if isinstance(obj, dict):
            return {k: self.event(v, (f"{key}.{k}" if key else str(k)).lower()) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.event(v, key) for v in obj]
        if not isinstance(obj, str) or not obj:
            return obj
        leaf = key.rsplit(".", 1)[-1]
        if key in HOST_KEYS or leaf in HOST_KEYS:
            return self.token("host", obj)
        if key in USER_KEYS or leaf in USER_KEYS:
            return self.token("user", obj)
        return self.text(obj)


def redact(event: dict) -> dict:
    """An event with addresses, host names and account names replaced by placeholders."""
    return Redactor().event(event)
