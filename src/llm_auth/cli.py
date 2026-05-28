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
DEFAULT_DEEP_RESEARCH_MODEL = "o4-mini-deep-research"
OPENAI_DEEP_RESEARCH_API_KEY_ENV = "OPENAI_DEEP_RESEARCH_API_KEY"
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


def quote_env(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:@%+=,-]+", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


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


def token_dir_from_env(env_file: Path, token_dir: Path | None) -> Path:
    load_dotenv(env_file)
    return (token_dir or Path(os.environ.get("CHATGPT_TOKEN_DIR", DEFAULT_TOKEN_DIR))).expanduser()


def auth_file_name_from_env(auth_file_name: str | None) -> str:
    return auth_file_name or os.environ.get("CHATGPT_AUTH_FILE", DEFAULT_AUTH_FILE)


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


def login(env_file: Path, token_dir: Path, auth_file_name: str, timeout: float) -> int:
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


def renew(env_file: Path, token_dir: Path, auth_file_name: str) -> int:
    configure_litellm_chatgpt_env(token_dir, auth_file_name)
    auth = read_auth(token_dir, auth_file_name)
    if not auth.refresh_token:
        print("chatgpt.renew: fail - refresh_token is missing")
        return 1
    try:
        install_env_chatgpt_auth(env_file, token_dir, auth_file_name)
        from litellm.llms.chatgpt.authenticator import Authenticator

        authenticator = Authenticator()
        authenticator._refresh_tokens(auth.refresh_token)
    except Exception as exc:  # noqa: BLE001 - CLI should report provider errors cleanly.
        print(f"chatgpt.renew: fail - {clean_error(str(exc), [auth.access_token, auth.refresh_token, auth.id_token])}")
        return 1
    print("chatgpt.renew: pass")
    return 0


def status(token_dir: Path, auth_file_name: str) -> int:
    auth = read_auth(token_dir, auth_file_name)
    deep_research_key = os.environ.get(OPENAI_DEEP_RESEARCH_API_KEY_ENV)
    expiry = auth_expiry_status(auth.expires_at)
    data = {
        "chatgpt": {
            "auth_json": env_auth_data() is not None,
            "access_token": auth.access_token is not None,
            "refresh_token": auth.refresh_token is not None,
            "account_id": auth.account_id is not None,
            **expiry,
        },
        "deepresearch": {
            "api_key": bool(deep_research_key),
        },
    }
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


def chatgpt_auth_json_subtest() -> TestResult:
    try:
        data = env_auth_data()
    except SystemExit as exc:
        return TestResult("chatgpt", "env-auth-json", False, str(exc))
    if data is None:
        return TestResult("chatgpt", "env-auth-json", False, f"{CHATGPT_AUTH_JSON_ENV} is missing")
    return TestResult("chatgpt", "env-auth-json", True)


def chatgpt_token_state_subtest(token_dir: Path, auth_file_name: str) -> TestResult:
    auth = read_auth(token_dir, auth_file_name)
    if not auth.access_token and not auth.refresh_token:
        return TestResult("chatgpt", "oauth-state", False, "missing access_token and refresh_token")
    now = int(time.time())
    if auth.expires_at is not None and now >= auth.expires_at - 60 and not auth.refresh_token:
        return TestResult("chatgpt", "oauth-state", False, "access_token is expired and refresh_token is missing")
    return TestResult("chatgpt", "oauth-state", True)


def chatgpt_completion_subtest(
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
        return TestResult("chatgpt", "completion", False, "run `llm-auth login`")
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
        return TestResult("chatgpt", "completion", False, detail)
    text = litellm_response_text(response)
    if text != "1":
        return TestResult("chatgpt", "completion", False, f"expected `1`, got {text!r}")
    return TestResult("chatgpt", "completion", True, f"model={model}")


def run_chatgpt_subtests(
    env_file: Path,
    token_dir: Path,
    auth_file_name: str,
    model: str,
    timeout: float,
    verbose: bool,
    show_raw_error: bool,
) -> list[TestResult]:
    return [
        chatgpt_auth_json_subtest(),
        chatgpt_token_state_subtest(token_dir, auth_file_name),
        chatgpt_completion_subtest(
            env_file,
            token_dir,
            auth_file_name,
            model,
            timeout,
            verbose,
            show_raw_error,
        ),
    ]


def deepresearch_api_key_subtest(env_file: Path) -> TestResult:
    load_dotenv(env_file)
    key = os.environ.get(OPENAI_DEEP_RESEARCH_API_KEY_ENV, "").strip()
    if not key:
        return TestResult("deepresearch", "api-key", False, f"{OPENAI_DEEP_RESEARCH_API_KEY_ENV} is missing")
    return TestResult("deepresearch", "api-key", True)


def deepresearch_model_subtest(env_file: Path, model: str, timeout: float) -> TestResult:
    load_dotenv(env_file)
    key = os.environ.get(OPENAI_DEEP_RESEARCH_API_KEY_ENV, "").strip()
    if not key:
        return TestResult("deepresearch", "model-access", False, f"{OPENAI_DEEP_RESEARCH_API_KEY_ENV} is missing")
    quoted_model = urllib.parse.quote(model, safe="")
    request = urllib.request.Request(
        f"{OPENAI_API_BASE}/models/{quoted_model}",
        headers={"Authorization": f"Bearer {key}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        return TestResult("deepresearch", "model-access", False, f"HTTP {exc.code}: {redact(detail, [key])}")
    except Exception as exc:
        return TestResult("deepresearch", "model-access", False, redact(str(exc), [key]))
    returned_model = data.get("id") if isinstance(data, dict) else None
    if returned_model != model:
        return TestResult("deepresearch", "model-access", False, f"expected model {model!r}, got {returned_model!r}")
    return TestResult("deepresearch", "model-access", True, f"model={model}")


def run_deepresearch_subtests(env_file: Path, model: str, timeout: float) -> list[TestResult]:
    return [
        deepresearch_api_key_subtest(env_file),
        deepresearch_model_subtest(env_file, model, timeout),
    ]


def test_all_surfaces(
    env_file: Path,
    token_dir: Path,
    auth_file_name: str,
    chatgpt_model: str,
    deepresearch_model: str,
    timeout: float,
    verbose: bool,
    show_raw_error: bool,
) -> int:
    surfaces = [
        (
            "chatgpt",
            run_chatgpt_subtests(
                env_file,
                token_dir,
                auth_file_name,
                chatgpt_model,
                timeout,
                verbose,
                show_raw_error,
            ),
        ),
        (
            "deepresearch",
            run_deepresearch_subtests(env_file, deepresearch_model, timeout),
        ),
    ]
    for surface, results in surfaces:
        print(format_surface_result(surface, results))
    return 0 if all(result.passed for _, results in surfaces for result in results) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage LLM auth for this repo.")
    parser.add_argument("--env-file", type=Path, default=DEFAULT_ENV_FILE)
    parser.add_argument("--token-dir", type=Path)
    parser.add_argument("--auth-file", default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser("login", help="Run LiteLLM ChatGPT OAuth device login.")
    login_parser.add_argument("--timeout", type=float, default=180)

    subparsers.add_parser("renew", help="Refresh ChatGPT OAuth tokens without device login.")

    subparsers.add_parser("status", help="Show redacted LiteLLM ChatGPT OAuth status.")

    test = subparsers.add_parser("test", help="Run LLM auth tests.")
    test.add_argument(
        "surface",
        nargs="?",
        choices=("chatgpt", "deepresearch", "deep-research"),
        help="Optional auth surface to test with detailed subtest output.",
    )
    test.add_argument(
        "--model",
        default=None,
        help="Model for the selected surface; for aggregate tests, overrides the ChatGPT model.",
    )
    test.add_argument(
        "--chatgpt-model",
        dest="chatgpt_model",
        default=None,
        help="LiteLLM chatgpt/* model to test.",
    )
    test.add_argument(
        "--deepresearch-model",
        "--deep-research-model",
        dest="deepresearch_model",
        default=None,
        help="OpenAI Deep Research model to test.",
    )
    test.add_argument("--timeout", type=float, default=60)
    test.add_argument("--verbose", action="store_true")
    test.add_argument("--show-raw-error", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        env_file = args.env_file.expanduser()
        token_dir = token_dir_from_env(env_file, args.token_dir)
        auth_file_name = auth_file_name_from_env(args.auth_file)

        if args.command == "login":
            return login(env_file, token_dir, auth_file_name, args.timeout)
        if args.command == "renew":
            return renew(env_file, token_dir, auth_file_name)
        if args.command == "status":
            return status(token_dir, auth_file_name)
        if args.command == "test":
            chatgpt_model = args.chatgpt_model or args.model or os.environ.get("LITELLM_CHATGPT_MODEL", DEFAULT_MODEL)
            deepresearch_model = (
                args.deepresearch_model
                or (
                    args.model
                    if args.surface in {"deepresearch", "deep-research"}
                    else None
                )
                or os.environ.get("OPENAI_DEEP_RESEARCH_MODEL", DEFAULT_DEEP_RESEARCH_MODEL)
            )
            if args.surface == "chatgpt":
                return print_test_results(
                    run_chatgpt_subtests(
                        env_file,
                        token_dir,
                        auth_file_name,
                        chatgpt_model,
                        args.timeout,
                        args.verbose,
                        args.show_raw_error,
                    )
                )
            if args.surface in {"deepresearch", "deep-research"}:
                return print_test_results(run_deepresearch_subtests(env_file, deepresearch_model, args.timeout))
            return test_all_surfaces(
                env_file,
                token_dir,
                auth_file_name,
                chatgpt_model,
                deepresearch_model,
                args.timeout,
                args.verbose,
                args.show_raw_error,
            )
        parser.error(f"unknown command: {args.command}")
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
