#!/usr/bin/env python3
"""Manage LLM auth state for this repo."""

from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import io
import json
import logging
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path.cwd()
DEFAULT_ENV_FILE = ROOT / ".env"
DEFAULT_TOKEN_DIR = ROOT / ".litellm-chatgpt"
DEFAULT_AUTH_FILE = "auth.json"
DEFAULT_MODEL = "chatgpt/gpt-5.4-mini"
CHATGPT_AUTH_JSON_ENV = "CHATGPT_AUTH_JSON"
OPENAI_API_BASE = "https://api.openai.com/v1"
ENV_METADATA_HEADER = "\n".join(
    [
        "# LLM auth store for this repo.",
        "# Bootstrap: add API-key env vars by hand; use llm-auth login for managed OAuth surfaces.",
        "# API-key surfaces are configured by env vars below.",
        "# Every auth surface should be wrapped in a BEGIN/END metadata envelope.",
        "# A surface may have multiple auth modes, such as api-key and subscription-oauth.",
        "# Managed OAuth surfaces may be refreshed by llm-auth.",
    ]
)
BEGIN_MARKER = "# BEGIN LLM AUTH SURFACE chatgpt subscription-oauth (managed by llm-auth)"
END_MARKER = "# END LLM AUTH SURFACE chatgpt subscription-oauth"
OLD_TOOL_SURFACE_BEGIN_MARKER = "# BEGIN LLM AUTH SURFACE chatgpt subscription-oauth (managed by tools/llm-auth)"
OLD_TOOL_LITELLM_AUTH_BEGIN_MARKER = "# BEGIN LITELLM CHATGPT OAUTH (managed by tools/llm-auth)"
OLD_LITELLM_AUTH_BEGIN_MARKER = "# BEGIN LITELLM CHATGPT OAUTH (managed by tools/litellm-auth)"
OLD_LITELLM_AUTH_END_MARKER = "# END LITELLM CHATGPT OAUTH"
LEGACY_BEGIN_MARKER = "# BEGIN CODEX OAUTH (managed by tools/codex_oauth_env.py)"
LEGACY_END_MARKER = "# END CODEX OAUTH"
LEGACY_LITELLM_BEGIN_MARKER = "# BEGIN LITELLM CHATGPT OAUTH (managed by tools/codex_oauth_env.py)"


@dataclass(frozen=True)
class ChatGPTAuth:
    token_dir: Path
    auth_file_name: str
    auth_file_path: Path
    access_token: str | None
    refresh_token: str | None
    id_token: str | None
    account_id: str | None
    expires_at: int | None


@dataclass(frozen=True)
class AuthSurface:
    name: str
    auth: str
    metadata: dict[str, str]
    env_keys: tuple[str, ...]

    @property
    def primary_env(self) -> str | None:
        return self.metadata.get("env") or (self.env_keys[0] if self.env_keys else None)


@dataclass(frozen=True)
class TestContext:
    env_file: Path
    token_dir: Path
    auth_file_name: str
    selected_model: str | None
    surface_models: dict[str, str]
    timeout: float
    verbose: bool
    show_raw_error: bool

    def model_for(self, surface: AuthSurface) -> str | None:
        if surface.name in self.surface_models:
            return self.surface_models[surface.name]
        if self.selected_model is not None:
            return self.selected_model
        if "model" in surface.metadata:
            return surface.metadata["model"]
        model_env = surface.metadata.get("model_env") or surface.metadata.get("model-env")
        if model_env:
            return os.environ.get(model_env)
        return None


@dataclass(frozen=True)
class TestResult:
    surface: str
    name: str
    passed: bool
    detail: str = ""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            try:
                value = ast.literal_eval(value)
            except (SyntaxError, ValueError):
                value = value[1:-1]
        os.environ.setdefault(key, value)


SURFACE_BEGIN_RE = re.compile(r"^# BEGIN LLM AUTH SURFACE\s+(\S+)\s+(\S+)(?:\s+\(.*\))?\s*$")
SURFACE_END_RE = re.compile(r"^# END LLM AUTH SURFACE\s+(\S+)\s+(\S+)\s*$")
ENV_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
SURFACE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def discover_auth_surfaces(env_file: Path) -> list[AuthSurface]:
    load_dotenv(env_file)
    if not env_file.exists():
        return []

    surfaces: list[AuthSurface] = []
    current: dict[str, Any] | None = None
    for line_number, raw_line in enumerate(env_file.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        begin = SURFACE_BEGIN_RE.match(line)
        if begin:
            if current is not None:
                raise SystemExit(f"error: nested auth surface envelope at {env_file}:{line_number}")
            name, auth = begin.groups()
            current = {
                "name": name,
                "auth": auth,
                "metadata": {"surface": name, "auth": auth},
                "env_keys": [],
                "line": line_number,
            }
            continue

        if current is None:
            continue

        end = SURFACE_END_RE.match(line)
        if end:
            end_name, end_auth = end.groups()
            if end_name != current["name"] or end_auth != current["auth"]:
                raise SystemExit(
                    f"error: auth surface envelope opened as {current['name']} {current['auth']} "
                    f"but closed as {end_name} {end_auth} at {env_file}:{line_number}"
                )
            env_keys = list(dict.fromkeys(current["env_keys"]))
            metadata = dict(current["metadata"])
            metadata_env = metadata.get("env")
            if metadata_env and metadata_env not in env_keys:
                env_keys.insert(0, metadata_env)
            surfaces.append(
                AuthSurface(
                    name=current["name"],
                    auth=current["auth"],
                    metadata=metadata,
                    env_keys=tuple(env_keys),
                )
            )
            current = None
            continue

        if line.startswith("#"):
            comment = line[1:].strip()
            if "=" in comment:
                key, value = comment.split("=", 1)
                current["metadata"][key.strip()] = value.strip()
            continue

        if "=" in line:
            key, _ = line.split("=", 1)
            key = key.strip()
            if key:
                current["env_keys"].append(key)

    if current is not None:
        raise SystemExit(
            f"error: auth surface envelope opened at {env_file}:{current['line']} "
            "without a matching END marker"
        )
    return surfaces


def quote_env(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:@%+=,-]+", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


def api_key_env_name(surface: str, provider: str) -> str:
    raw = f"{provider}_{surface}_api_key"
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", raw).strip("_").upper()
    if not normalized:
        raise SystemExit("error: could not derive an env var name")
    if normalized[0].isdigit():
        normalized = f"LLM_{normalized}"
    return normalized


def validate_surface_name(surface: str) -> None:
    if not SURFACE_NAME_RE.fullmatch(surface):
        raise SystemExit(
            "error: surface must contain only letters, digits, dot, underscore, or dash"
        )


def validate_env_key(env_key: str) -> None:
    if not ENV_KEY_RE.fullmatch(env_key):
        raise SystemExit(
            "error: env var name must be uppercase and contain only letters, digits, and underscore"
        )


def append_api_key_surface(
    *,
    env_file: Path,
    allow_unignored: bool,
    surface: str,
    provider: str,
    env_key: str,
    model: str | None,
    api_base: str | None,
    key: str | None,
) -> None:
    validate_surface_name(surface)
    validate_env_key(env_key)
    provider = provider.strip().lower()
    if not provider:
        raise SystemExit("error: provider is required")
    if not allow_unignored and not is_ignored_root_env(env_file):
        raise SystemExit(
            f"error: refusing to write API key surface to {env_file}; only ignored repo-root .env is allowed"
        )

    existing = discover_auth_surfaces(env_file)
    for auth_surface in existing:
        if auth_surface.name == surface and auth_surface.auth == "api-key":
            raise SystemExit(f"error: api-key surface {surface!r} already exists")
        if env_key in auth_surface.env_keys:
            raise SystemExit(f"error: env var {env_key!r} already belongs to a surface")

    value = quote_env(key) if key is not None else ""
    metadata = [
        f"# BEGIN LLM AUTH SURFACE {surface} api-key",
        f"# surface={surface}",
        f"# provider={provider}",
        "# auth=api-key",
        f"# env={env_key}",
    ]
    if model:
        metadata.append(f"# model={model}")
    if api_base:
        metadata.append(f"# api_base={api_base}")
    metadata.extend(
        [
            f"{env_key}={value}",
            f"# END LLM AUTH SURFACE {surface} api-key",
        ]
    )
    block = "\n".join(metadata) + "\n"

    if env_file.exists():
        current = env_file.read_text(encoding="utf-8")
        prefix = "" if current.endswith("\n") or not current else "\n"
        content = f"{current}{prefix}\n{block}" if current.strip() else f"{ENV_METADATA_HEADER}\n\n{block}"
    else:
        content = f"{ENV_METADATA_HEADER}\n\n{block}"
    env_file.parent.mkdir(parents=True, exist_ok=True)
    env_file.write_text(content, encoding="utf-8")
    try:
        env_file.chmod(0o600)
    except OSError as exc:
        print(f"warning: could not restrict {env_file} permissions: {exc}", file=sys.stderr)


def add_api_key(args: argparse.Namespace) -> int:
    env_file = args.env_file.expanduser()
    env_key = args.env or api_key_env_name(args.surface, args.provider)
    append_api_key_surface(
        env_file=env_file,
        allow_unignored=args.allow_unignored,
        surface=args.surface,
        provider=args.provider,
        env_key=env_key,
        model=args.model,
        api_base=args.api_base,
        key=args.key,
    )
    key_detail = "with key" if args.key is not None else "without key"
    print(f"added {args.surface} api-key surface for {args.provider} using {env_key} ({key_detail})")
    return 0


def redact(message: str, secrets: list[str | None]) -> str:
    redacted = message
    for secret in secrets:
        if not secret:
            continue
        redacted = redacted.replace(secret, "[redacted]")
        if len(secret) > 12:
            redacted = redacted.replace(secret[:8], "[redacted-prefix]")
            redacted = redacted.replace(secret[-6:], "[redacted-suffix]")
    return redacted


def clean_error(message: str, secrets: list[str | None]) -> str:
    message = redact(message, secrets)
    if "<html" in message.lower() or "cf_chl" in message:
        return "ChatGPT backend returned an HTML/Cloudflare challenge"
    message = re.sub(r"\x1b\[[0-9;]*m", "", message)
    lines = [
        line.strip()
        for line in message.splitlines()
        if line.strip()
        and "Provider List:" not in line
        and "Give Feedback / Get Help:" not in line
        and "LiteLLM.Info:" not in line
    ]
    compact = " ".join(lines) if lines else message.strip()
    return compact[:500]


def clean_http_error(exc: urllib.error.HTTPError, secrets: list[str | None]) -> str:
    body = exc.read().decode("utf-8", errors="replace")
    return f"HTTP {exc.code}: {clean_error(body, secrets)}"


def raw_error_body(message: str, secrets: list[str | None]) -> str:
    message = redact(message, secrets)
    html_start = message.lower().find("<html")
    if html_start >= 0:
        return message[html_start:]
    return message


def decode_jwt_claims(token: str | None) -> dict[str, Any]:
    if not token:
        return {}
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
    except Exception:
        return {}


def token_expiry(token: str | None) -> int | None:
    exp = decode_jwt_claims(token).get("exp")
    if isinstance(exp, (int, float)):
        return int(exp)
    return None


def human_duration(seconds: int) -> str:
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    days, remainder = divmod(seconds, 24 * 60 * 60)
    hours, remainder = divmod(remainder, 60 * 60)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{sign}{days}d {hours}h"
    if hours:
        return f"{sign}{hours}h {minutes}m"
    if minutes:
        return f"{sign}{minutes}m {seconds}s"
    return f"{sign}{seconds}s"


def auth_expiry_status(expires_at: int | None, now: int | None = None) -> dict[str, Any]:
    if now is None:
        now = int(time.time())
    expired = expires_at is not None and now >= expires_at - 60
    return {
        "expires_at": expires_at,
        "expires_in": human_duration(expires_at - now) if expires_at is not None else None,
        "expired": expired,
    }


def chatgpt_compat_auth_location() -> tuple[Path, str]:
    return DEFAULT_TOKEN_DIR.expanduser(), DEFAULT_AUTH_FILE


def configure_litellm_chatgpt_env(token_dir: Path, auth_file_name: str) -> None:
    os.environ["CHATGPT_TOKEN_DIR"] = str(token_dir)
    os.environ["CHATGPT_AUTH_FILE"] = auth_file_name
    os.environ.setdefault("LITELLM_LOG", "ERROR")
    logging.getLogger("LiteLLM").setLevel(logging.ERROR)
    logging.getLogger("litellm").setLevel(logging.ERROR)


def env_auth_data() -> dict[str, Any] | None:
    raw = os.environ.get(CHATGPT_AUTH_JSON_ENV, "").strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {CHATGPT_AUTH_JSON_ENV} did not contain valid JSON") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"error: {CHATGPT_AUTH_JSON_ENV} did not contain a JSON object")
    return data


def read_auth_data(token_dir: Path, auth_file_name: str) -> tuple[Path, dict[str, Any]]:
    auth_file = token_dir / auth_file_name
    data: dict[str, Any] = {}
    env_data = env_auth_data()
    if env_data is not None:
        data = env_data
    return auth_file, data


def read_auth(token_dir: Path, auth_file_name: str) -> ChatGPTAuth:
    auth_file, data = read_auth_data(token_dir, auth_file_name)
    access_token = as_optional_str(data.get("access_token"))
    refresh_token = as_optional_str(data.get("refresh_token"))
    id_token = as_optional_str(data.get("id_token"))
    expires_at = data.get("expires_at")
    if not isinstance(expires_at, int):
        expires_at = token_expiry(access_token)
    return ChatGPTAuth(
        token_dir=token_dir,
        auth_file_name=auth_file_name,
        auth_file_path=auth_file,
        access_token=access_token,
        refresh_token=refresh_token,
        id_token=id_token,
        account_id=as_optional_str(data.get("account_id")),
        expires_at=expires_at,
    )


def as_optional_str(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def is_ignored_root_env(path: Path) -> bool:
    try:
        rel = path.resolve().relative_to(ROOT.resolve())
    except ValueError:
        return False
    if rel.as_posix() != ".env":
        return False
    gitignore = ROOT / ".gitignore"
    if not gitignore.exists():
        return False
    patterns = {
        raw.strip()
        for raw in gitignore.read_text(encoding="utf-8").splitlines()
        if raw.strip() and not raw.lstrip().startswith("#")
    }
    return ".env" in patterns or "/.env" in patterns or "*.env" in patterns


def split_managed_block(text: str) -> tuple[str, str, bool]:
    start = text.find(BEGIN_MARKER)
    if start == -1:
        return text.rstrip("\n"), "", False
    end = text.find(END_MARKER, start)
    if end == -1:
        raise SystemExit(f"error: found {BEGIN_MARKER!r} without matching {END_MARKER!r}")
    end += len(END_MARKER)
    return text[:start].rstrip("\n"), text[end:].strip("\n"), True


def remove_legacy_block(text: str) -> str:
    for begin_marker, end_marker in [
        (OLD_TOOL_SURFACE_BEGIN_MARKER, END_MARKER),
        (OLD_TOOL_LITELLM_AUTH_BEGIN_MARKER, OLD_LITELLM_AUTH_END_MARKER),
        (OLD_LITELLM_AUTH_BEGIN_MARKER, OLD_LITELLM_AUTH_END_MARKER),
        (LEGACY_BEGIN_MARKER, LEGACY_END_MARKER),
        (LEGACY_LITELLM_BEGIN_MARKER, OLD_LITELLM_AUTH_END_MARKER),
    ]:
        start = text.find(begin_marker)
        if start == -1:
            continue
        end = text.find(end_marker, start)
        if end == -1:
            raise SystemExit(f"error: found {begin_marker!r} without matching {end_marker!r}")
        end += len(end_marker)
        before = text[:start].rstrip("\n")
        after = text[end:].strip("\n")
        text = "\n\n".join(piece for piece in [before, after] if piece)
        if text:
            text += "\n"
    return text


def ensure_env_metadata_header(text: str) -> str:
    text = text.lstrip("\n")
    if text.startswith(ENV_METADATA_HEADER):
        return text
    return f"{ENV_METADATA_HEADER}\n\n{text}" if text else f"{ENV_METADATA_HEADER}\n"


def render_env_block(auth_json: str) -> str:
    lines = [
        BEGIN_MARKER,
        "# surface=chatgpt",
        "# auth=subscription-oauth",
        f"# env={CHATGPT_AUTH_JSON_ENV}",
        "# renew=true",
        f"{CHATGPT_AUTH_JSON_ENV}={quote_env(auth_json)}",
    ]
    lines.extend(
        [
            f"LITELLM_CHATGPT_AUTH_SYNCED_AT={quote_env(utc_now())}",
            END_MARKER,
        ]
    )
    return "\n".join(
        lines
    )


def default_chatgpt_surface() -> AuthSurface:
    return AuthSurface(
        name="chatgpt",
        auth="subscription-oauth",
        metadata={
            "surface": "chatgpt",
            "auth": "subscription-oauth",
            "env": CHATGPT_AUTH_JSON_ENV,
            "renew": "true",
        },
        env_keys=(CHATGPT_AUTH_JSON_ENV,),
    )


def write_env_block(
    env_file: Path,
    allow_unignored: bool,
    dry_run: bool,
    auth_json: str,
    quiet: bool = False,
) -> None:
    if not allow_unignored and not is_ignored_root_env(env_file):
        raise SystemExit(
            f"error: refusing to write auth settings to {env_file}; only ignored repo-root .env is allowed"
        )
    text = env_file.read_text(encoding="utf-8") if env_file.exists() else ""
    text = remove_legacy_block(text)
    before, after, had_block = split_managed_block(text)
    pieces = [piece for piece in [before, render_env_block(auth_json), after] if piece]
    rendered = ensure_env_metadata_header("\n\n".join(pieces) + "\n")
    if dry_run:
        print("ok: dry-run")
        return
    env_file.write_text(rendered, encoding="utf-8")
    try:
        env_file.chmod(stat.S_IMODE(env_file.stat().st_mode) & 0o600)
    except OSError as exc:
        print(f"warning: could not restrict {env_file} permissions: {exc}", file=sys.stderr)
    if not quiet:
        print(f"ok: {'updated' if had_block else 'added'}")


def write_auth_env_block(
    env_file: Path,
    data: dict[str, Any],
    allow_unignored: bool,
) -> None:
    auth_json = json.dumps(data, separators=(",", ":"), sort_keys=True)
    write_env_block(env_file, allow_unignored, dry_run=False, auth_json=auth_json, quiet=True)
    os.environ[CHATGPT_AUTH_JSON_ENV] = auth_json


def install_env_chatgpt_auth(env_file: Path, token_dir: Path, auth_file_name: str) -> None:
    from litellm.llms.chatgpt import authenticator as authenticator_module

    original = authenticator_module.Authenticator

    class EnvAuthenticator(original):  # type: ignore[misc, valid-type]
        def __init__(self) -> None:
            self.token_dir = str(token_dir)
            self.auth_file = str(token_dir / auth_file_name)

        def _ensure_token_dir(self) -> None:
            return None

        def _read_auth_file(self) -> dict[str, Any] | None:
            return env_auth_data()

        def _write_auth_file(self, data: dict[str, Any]) -> None:
            write_auth_env_block(env_file, data, allow_unignored=False)

    authenticator_module.Authenticator = EnvAuthenticator
    for module_name in [
        "litellm.llms.chatgpt.chat.transformation",
        "litellm.llms.chatgpt.responses.transformation",
    ]:
        module = sys.modules.get(module_name)
        if module is not None:
            setattr(module, "Authenticator", EnvAuthenticator)


def poll_for_authorization_code(authenticator: Any, device_code: dict[str, str], timeout: float) -> dict[str, str] | None:
    from litellm.llms.chatgpt.common_utils import CHATGPT_DEVICE_TOKEN_URL
    from litellm.llms.custom_httpx.http_handler import _get_httpx_client

    client = _get_httpx_client()
    interval = int(device_code.get("interval", "5"))
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = client.post(
                CHATGPT_DEVICE_TOKEN_URL,
                json={
                    "device_auth_id": device_code["device_auth_id"],
                    "user_code": device_code["user_code"],
                },
            )
            if response.status_code == 200:
                data = response.json()
                if all(key in data for key in ("authorization_code", "code_challenge", "code_verifier")):
                    return data
            elif response.status_code not in (403, 404):
                response.raise_for_status()
        except Exception as exc:
            print(f"error: login polling failed: {exc}", file=sys.stderr)
            return None
        sleep_for = min(max(interval, 5), max(0.0, deadline - time.time()))
        if sleep_for <= 0:
            break
        time.sleep(sleep_for)
    return None


def supports_chatgpt_oauth(surface: AuthSurface) -> bool:
    return surface.auth == "subscription-oauth" and surface.primary_env == CHATGPT_AUTH_JSON_ENV


def is_renewable(surface: AuthSurface) -> bool:
    return surface.metadata.get("renew", "").lower() == "true"


def available_surface_names(surfaces: list[AuthSurface]) -> str:
    return ", ".join(dict.fromkeys(surface.name for surface in surfaces)) or "none"


def resolve_login_surface(surface_name: str | None, surfaces: list[AuthSurface]) -> AuthSurface | None:
    candidates = [surface for surface in surfaces if supports_chatgpt_oauth(surface)]
    if surface_name is None:
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            return default_chatgpt_surface()
        print(
            f"error: multiple login-capable surfaces; choose one: {available_surface_names(candidates)}",
            file=sys.stderr,
        )
        return None
    for surface in surfaces:
        if surface.name == surface_name:
            if supports_chatgpt_oauth(surface):
                return surface
            print(f"error: surface {surface_name!r} does not support login", file=sys.stderr)
            return None
    if surface_name == "chatgpt":
        return default_chatgpt_surface()
    print(f"error: unknown auth surface {surface_name!r}; available: {available_surface_names(surfaces)}", file=sys.stderr)
    return None


def login_chatgpt(env_file: Path, surface: AuthSurface, token_dir: Path, auth_file_name: str, timeout: float) -> int:
    configure_litellm_chatgpt_env(token_dir, auth_file_name)
    try:
        install_env_chatgpt_auth(env_file, token_dir, auth_file_name)
        from litellm.llms.chatgpt.authenticator import Authenticator
    except ImportError as exc:
        raise SystemExit("error: LiteLLM ChatGPT provider is not installed") from exc

    authenticator = Authenticator()
    auth_data = authenticator._read_auth_file() or {}
    access_token = auth_data.get("access_token")
    if access_token and not authenticator._is_token_expired(auth_data, access_token):
        print("ok")
        return 0
    refresh_token = auth_data.get("refresh_token")
    if refresh_token:
        try:
            authenticator._refresh_tokens(refresh_token)
            print("ok")
            return 0
        except Exception:
            pass

    cooldown_remaining = authenticator._get_device_code_cooldown_remaining(auth_data)
    if cooldown_remaining > 0:
        print(f"error: device-code cooldown active; retry in {int(cooldown_remaining)}s", file=sys.stderr)
        return 1

    try:
        device_code = authenticator._request_device_code()
        authenticator._record_device_code_request()
    except Exception as exc:
        print(f"error: failed to request device code: {exc}", file=sys.stderr)
        return 1

    print("Sign in with ChatGPT using device code:", flush=True)
    print("1) Visit https://auth.openai.com/codex/device", flush=True)
    print(f"2) Enter code: {device_code['user_code']}", flush=True)
    print("Device codes are a common phishing target. Never share this code.", flush=True)

    authorization_code = poll_for_authorization_code(authenticator, device_code, timeout)
    if authorization_code is None:
        print("error: login timed out", file=sys.stderr)
        return 1
    try:
        tokens = authenticator._exchange_code_for_tokens(authorization_code)
        authenticator._write_auth_file(authenticator._build_auth_record(tokens))
    except Exception as exc:
        print(f"error: token exchange failed: {exc}", file=sys.stderr)
        return 1
    print("ok")
    return 0


def login(env_file: Path, surface_name: str | None, surfaces: list[AuthSurface], timeout: float) -> int:
    surface = resolve_login_surface(surface_name, surfaces)
    if surface is None:
        return 2
    token_dir, auth_file_name = chatgpt_compat_auth_location()
    if supports_chatgpt_oauth(surface):
        return login_chatgpt(env_file, surface, token_dir, auth_file_name, timeout)
    print(f"error: no login handler for {surface.name} {surface.auth}", file=sys.stderr)
    return 2


def renew_chatgpt(env_file: Path, surface: AuthSurface, token_dir: Path, auth_file_name: str) -> TestResult:
    configure_litellm_chatgpt_env(token_dir, auth_file_name)
    auth = read_auth(token_dir, auth_file_name)
    if not auth.refresh_token:
        return TestResult(surface.name, "renew", False, "refresh_token is missing")
    try:
        install_env_chatgpt_auth(env_file, token_dir, auth_file_name)
        from litellm.llms.chatgpt.authenticator import Authenticator

        authenticator = Authenticator()
        authenticator._refresh_tokens(auth.refresh_token)
    except Exception as exc:  # noqa: BLE001 - CLI should report provider errors cleanly.
        return TestResult(
            surface.name,
            "renew",
            False,
            clean_error(str(exc), [auth.access_token, auth.refresh_token, auth.id_token]),
        )
    return TestResult(surface.name, "renew", True)


def run_surface_renew(surface: AuthSurface, env_file: Path) -> TestResult:
    if supports_chatgpt_oauth(surface):
        token_dir, auth_file_name = chatgpt_compat_auth_location()
        return renew_chatgpt(env_file, surface, token_dir, auth_file_name)
    return TestResult(surface.name, "renew", False, "no renew handler for this auth mode")


def print_renew_result(result: TestResult) -> None:
    status_text = "pass" if result.passed else "fail"
    line = f"{result.surface}.renew: {status_text}"
    if result.detail:
        line += f" - {result.detail}"
    print(line)


def renew(env_file: Path, surface_name: str | None, surfaces: list[AuthSurface]) -> int:
    if surface_name is None:
        selected = [surface for surface in surfaces if is_renewable(surface)]
        if not selected:
            print("error: no renewable auth surfaces found", file=sys.stderr)
            return 1
    else:
        selected = [surface for surface in surfaces if surface.name == surface_name]
        if not selected:
            if surface_name == "chatgpt" and env_auth_data() is not None:
                selected = [default_chatgpt_surface()]
            else:
                print(
                    f"error: unknown auth surface {surface_name!r}; available: {available_surface_names(surfaces)}",
                    file=sys.stderr,
                )
                return 2
    results = [run_surface_renew(surface, env_file) for surface in selected]
    for result in results:
        print_renew_result(result)
    return 0 if all(result.passed for result in results) else 1


def chatgpt_status(surface: AuthSurface, token_dir: Path, auth_file_name: str) -> dict[str, Any]:
    auth = read_auth(token_dir, auth_file_name)
    expiry = auth_expiry_status(auth.expires_at)
    return {
        "auth": surface.auth,
        "env": surface.primary_env,
        "auth_json": env_auth_data() is not None,
        "access_token": auth.access_token is not None,
        "refresh_token": auth.refresh_token is not None,
        "account_id": auth.account_id is not None,
        **expiry,
    }


def api_key_status(surface: AuthSurface) -> dict[str, Any]:
    env_key = surface.primary_env
    return {
        "auth": surface.auth,
        "env": env_key,
        "api_key": bool(env_key and os.environ.get(env_key, "").strip()),
    }


def surface_status(surface: AuthSurface) -> dict[str, Any]:
    if supports_chatgpt_oauth(surface):
        token_dir, auth_file_name = chatgpt_compat_auth_location()
        return chatgpt_status(surface, token_dir, auth_file_name)
    if surface.auth == "api-key":
        return api_key_status(surface)
    return {
        "auth": surface.auth,
        "env": surface.primary_env,
        "configured": any(os.environ.get(env_key, "").strip() for env_key in surface.env_keys),
    }


def status(surface_name: str | None, surfaces: list[AuthSurface]) -> int:
    if surface_name is None:
        selected = surfaces
    else:
        selected = [surface for surface in surfaces if surface.name == surface_name]
        if not selected:
            print(f"error: unknown auth surface {surface_name!r}; available: {available_surface_names(surfaces)}", file=sys.stderr)
            return 2
    data: dict[str, Any] = {}
    for surface in selected:
        current = surface_status(surface)
        if surface.name in data:
            existing = data[surface.name]
            if isinstance(existing, list):
                existing.append(current)
            else:
                data[surface.name] = [existing, current]
        else:
            data[surface.name] = current
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def litellm_response_text(response: object) -> str:
    choices = response.get("choices") if isinstance(response, dict) else getattr(response, "choices", None)
    if not choices:
        return ""
    first = choices[0]
    message = first.get("message") if isinstance(first, dict) else getattr(first, "message", None)
    if isinstance(message, dict):
        return str(message.get("content") or "").strip()
    return str(getattr(message, "content", "") or "").strip()


def format_test_result(result: TestResult) -> str:
    status = "pass" if result.passed else "fail"
    line = f"{result.surface}.{result.name}: {status}"
    if result.detail:
        line += f" - {result.detail}"
    return line


def format_surface_result(surface: str, results: list[TestResult]) -> str:
    failed = [result for result in results if not result.passed]
    if not failed:
        return f"{surface}: pass"
    if len(failed) == 1:
        result = failed[0]
        line = f"{surface}: fail - {result.name}"
        if result.detail:
            line += f": {result.detail}"
        return line
    return f"{surface}: fail - subtests: {', '.join(result.name for result in failed)}"


def print_test_results(results: list[TestResult]) -> int:
    for result in results:
        print(format_test_result(result))
    return 0 if all(result.passed for result in results) else 1


def chatgpt_auth_json_subtest(surface: AuthSurface) -> TestResult:
    try:
        data = env_auth_data()
    except SystemExit as exc:
        return TestResult(surface.name, "subscription-oauth.env-auth-json", False, str(exc))
    if data is None:
        return TestResult(surface.name, "subscription-oauth.env-auth-json", False, f"{CHATGPT_AUTH_JSON_ENV} is missing")
    return TestResult(surface.name, "subscription-oauth.env-auth-json", True)


def chatgpt_token_state_subtest(surface: AuthSurface, token_dir: Path, auth_file_name: str) -> TestResult:
    auth = read_auth(token_dir, auth_file_name)
    if not auth.access_token and not auth.refresh_token:
        return TestResult(surface.name, "subscription-oauth.oauth-state", False, "missing access_token and refresh_token")
    now = int(time.time())
    if auth.expires_at is not None and now >= auth.expires_at - 60 and not auth.refresh_token:
        return TestResult(
            surface.name,
            "subscription-oauth.oauth-state",
            False,
            "access_token is expired and refresh_token is missing",
        )
    return TestResult(surface.name, "subscription-oauth.oauth-state", True)


def chatgpt_completion_subtest(
    surface: AuthSurface,
    env_file: Path,
    token_dir: Path,
    auth_file_name: str,
    model: str,
    timeout: float,
    verbose: bool,
    show_raw_error: bool,
) -> TestResult:
    configure_litellm_chatgpt_env(token_dir, auth_file_name)
    auth = read_auth(token_dir, auth_file_name)
    if not auth.access_token and not auth.refresh_token:
        return TestResult(surface.name, "subscription-oauth.completion", False, "run `llm-auth login`")
    try:
        install_env_chatgpt_auth(env_file, token_dir, auth_file_name)
        import litellm

        litellm.suppress_debug_info = True
        if verbose:
            response = litellm.completion(
                model=model,
                messages=[{"role": "user", "content": "Respond with exactly: 1"}],
                max_tokens=3,
                timeout=timeout,
            )
        else:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                response = litellm.completion(
                    model=model,
                    messages=[{"role": "user", "content": "Respond with exactly: 1"}],
                    max_tokens=3,
                    timeout=timeout,
                )
    except Exception as exc:  # noqa: BLE001 - CLI should report provider errors cleanly.
        if show_raw_error:
            detail = raw_error_body(str(exc), [auth.access_token, auth.refresh_token, auth.id_token])
        else:
            detail = clean_error(str(exc), [auth.access_token, auth.refresh_token, auth.id_token])
        return TestResult(surface.name, "subscription-oauth.completion", False, detail)
    text = litellm_response_text(response)
    if text != "1":
        return TestResult(surface.name, "subscription-oauth.completion", False, f"expected `1`, got {text!r}")
    return TestResult(surface.name, "subscription-oauth.completion", True, f"model={model}")


def run_chatgpt_subtests(
    surface: AuthSurface,
    context: TestContext,
) -> list[TestResult]:
    model = context.model_for(surface) or os.environ.get("LITELLM_CHATGPT_MODEL", DEFAULT_MODEL)
    results = [
        chatgpt_auth_json_subtest(surface),
        chatgpt_token_state_subtest(surface, context.token_dir, context.auth_file_name),
    ]
    if surface.metadata.get("live_backend", "").lower() == "true":
        results.append(
            chatgpt_completion_subtest(
                surface,
                context.env_file,
                context.token_dir,
                context.auth_file_name,
                model,
                context.timeout,
                context.verbose,
                context.show_raw_error,
            )
        )
    return results


def api_key_subtest(surface: AuthSurface) -> TestResult:
    env_key = surface.primary_env
    if not env_key:
        return TestResult(surface.name, "api-key", False, "metadata is missing env=<ENV_VAR>")
    key = os.environ.get(env_key, "").strip()
    if not key:
        return TestResult(surface.name, "api-key", False, f"{env_key} is missing")
    return TestResult(surface.name, "api-key", True)


def openai_model_access_subtest(surface: AuthSurface, model: str, timeout: float) -> TestResult:
    env_key = surface.primary_env
    if not env_key:
        return TestResult(surface.name, "openai-model-access", False, "metadata is missing env=<ENV_VAR>")
    key = os.environ.get(env_key, "").strip()
    if not key:
        return TestResult(surface.name, "openai-model-access", False, f"{env_key} is missing")
    quoted_model = urllib.parse.quote(model, safe="")
    request = urllib.request.Request(
        f"{surface.metadata.get('api_base', OPENAI_API_BASE)}/models/{quoted_model}",
        headers={"Authorization": f"Bearer {key}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return TestResult(surface.name, "openai-model-access", False, clean_http_error(exc, [key]))
    except Exception as exc:
        return TestResult(surface.name, "openai-model-access", False, redact(str(exc), [key]))
    returned_model = data.get("id") if isinstance(data, dict) else None
    if returned_model != model:
        return TestResult(
            surface.name,
            "openai-model-access",
            False,
            f"expected model {model!r}, got {returned_model!r}",
        )
    return TestResult(surface.name, "openai-model-access", True, f"model={model}")


def response_output_text(data: dict[str, Any]) -> str:
    output_text = data.get("output_text")
    if isinstance(output_text, str):
        return output_text.strip()
    output = data.get("output")
    if not isinstance(output, list):
        return ""
    pieces: list[str] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, dict):
                continue
            text = part.get("text")
            if isinstance(text, str):
                pieces.append(text)
    return "".join(pieces).strip()


def openai_response_subtest(surface: AuthSurface, model: str, timeout: float) -> TestResult:
    env_key = surface.primary_env
    if not env_key:
        return TestResult(surface.name, "openai-response", False, "metadata is missing env=<ENV_VAR>")
    key = os.environ.get(env_key, "").strip()
    if not key:
        return TestResult(surface.name, "openai-response", False, f"{env_key} is missing")
    payload = json.dumps(
        {
            "model": model,
            "input": "Respond with exactly: 1",
            "max_output_tokens": 128,
            "store": False,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{surface.metadata.get('api_base', OPENAI_API_BASE)}/responses",
        data=payload,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return TestResult(surface.name, "openai-response", False, clean_http_error(exc, [key]))
    except Exception as exc:
        return TestResult(surface.name, "openai-response", False, redact(str(exc), [key]))
    text = response_output_text(data)
    if text != "1":
        return TestResult(surface.name, "openai-response", False, f"expected `1`, got {text!r}")
    return TestResult(surface.name, "openai-response", True, f"model={model}")


def run_api_key_subtests(surface: AuthSurface, context: TestContext) -> list[TestResult]:
    results = [api_key_subtest(surface)]
    model = context.model_for(surface)
    if surface.metadata.get("provider") == "openai" and model:
        results.append(openai_model_access_subtest(surface, model, context.timeout))
        results.append(openai_response_subtest(surface, model, context.timeout))
    return results


def run_surface_subtests(surface: AuthSurface, context: TestContext) -> list[TestResult]:
    if surface.auth == "subscription-oauth" and surface.primary_env == CHATGPT_AUTH_JSON_ENV:
        return run_chatgpt_subtests(surface, context)
    if surface.auth == "api-key":
        return run_api_key_subtests(surface, context)
    return [TestResult(surface.name, surface.auth, False, "no test handler for this auth mode")]


def test_all_surfaces(
    surfaces: list[AuthSurface],
    context: TestContext,
) -> int:
    grouped: dict[str, list[TestResult]] = {}
    for surface in surfaces:
        grouped.setdefault(surface.name, []).extend(run_surface_subtests(surface, context))
    for surface, results in grouped.items():
        print(format_surface_result(surface, results))
    return 0 if all(result.passed for results in grouped.values() for result in results) else 1


def test_one_surface(surface_name: str, surfaces: list[AuthSurface], context: TestContext) -> int:
    matches = [surface for surface in surfaces if surface.name == surface_name]
    if not matches:
        available = ", ".join(dict.fromkeys(surface.name for surface in surfaces)) or "none"
        print(f"error: unknown auth surface {surface_name!r}; available: {available}", file=sys.stderr)
        return 2
    results: list[TestResult] = []
    for surface in matches:
        results.extend(run_surface_subtests(surface, context))
    return print_test_results(results)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage LLM auth for this repo.")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser("login", help="Run OAuth login for a managed auth surface.")
    login_parser.add_argument("surface", nargs="?", help="Auth surface to log in.")
    login_parser.add_argument("--timeout", type=float, default=180)

    renew_parser = subparsers.add_parser("renew", help="Refresh renewable auth surfaces without device login.")
    renew_parser.add_argument("surface", nargs="?", help="Optional auth surface to renew.")

    add_api_key_parser = subparsers.add_parser(
        "add-api-key",
        help="Add an API-key auth surface envelope to the env file.",
    )
    add_api_key_parser.add_argument("surface", help="Surface name, for example lead-finder.")
    add_api_key_parser.add_argument("provider", help="Provider name, for example openai.")
    add_api_key_parser.add_argument(
        "--env",
        help="Environment variable name. Defaults to PROVIDER_SURFACE_API_KEY.",
    )
    add_api_key_parser.add_argument("--model", help="Default model metadata for this surface.")
    add_api_key_parser.add_argument("--api-base", help="Provider API base metadata.")
    add_api_key_parser.add_argument(
        "--key",
        help="Optional API key value. If omitted, an empty env assignment is written.",
    )
    add_api_key_parser.add_argument(
        "--allow-unignored",
        action="store_true",
        help="Allow writing to an env file that is not ignored by the repo.",
    )

    status_parser = subparsers.add_parser("status", help="Show redacted auth surface status as JSON.")
    status_parser.add_argument("surface", nargs="?", help="Optional auth surface to inspect.")

    test = subparsers.add_parser("test", help="Run LLM auth tests.")
    test.add_argument(
        "surface",
        nargs="?",
        help="Optional auth surface from the configured auth store to test with detailed subtest output.",
    )
    test.add_argument(
        "--model",
        default=None,
        help="Model for the selected surface. For aggregate tests, use --surface-model SURFACE=MODEL.",
    )
    test.add_argument("--surface-model", action="append", default=[], metavar="SURFACE=MODEL")
    test.add_argument("--timeout", type=float, default=60)
    test.add_argument("--verbose", action="store_true")
    test.add_argument("--show-raw-error", action="store_true")

    return parser


def parse_surface_model_overrides(values: list[str], parser: argparse.ArgumentParser) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            parser.error(f"--surface-model expects SURFACE=MODEL, got {value!r}")
        surface, model = value.split("=", 1)
        surface = surface.strip()
        model = model.strip()
        if not surface or not model:
            parser.error(f"--surface-model expects SURFACE=MODEL, got {value!r}")
        overrides[surface] = model
    return overrides


def main(argv: list[str] | None = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        env_file = args.env_file.expanduser()
        load_dotenv(env_file)
        surfaces = discover_auth_surfaces(env_file)

        if args.command == "login":
            return login(env_file, args.surface, surfaces, args.timeout)
        if args.command == "renew":
            return renew(env_file, args.surface, surfaces)
        if args.command == "add-api-key":
            return add_api_key(args)
        if args.command == "status":
            return status(args.surface, surfaces)
        if args.command == "test":
            if args.model and not args.surface:
                parser.error("--model requires a surface; use --surface-model SURFACE=MODEL for aggregate tests")
            if not surfaces:
                print(f"error: no auth surfaces found in {env_file}", file=sys.stderr)
                return 1
            token_dir, auth_file_name = chatgpt_compat_auth_location()
            context = TestContext(
                env_file,
                token_dir,
                auth_file_name,
                args.model,
                parse_surface_model_overrides(args.surface_model, parser),
                args.timeout,
                args.verbose,
                args.show_raw_error,
            )
            if args.surface:
                return test_one_surface(args.surface, surfaces, context)
            return test_all_surfaces(surfaces, context)
        parser.error(f"unknown command: {args.command}")
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
