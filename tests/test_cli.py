import io
import json
import sys
import tomllib
import types
import urllib.error
from pathlib import Path

import pytest

from llm_auth import cli


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def ignored_env_repo(tmp_path: Path) -> Path:
    (tmp_path / ".git" / "info").mkdir(parents=True)
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    return tmp_path / ".env"


def test_add_api_key_writes_metadata_envelope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    env_file = ignored_env_repo(tmp_path)

    cli.append_api_key_surface(
        env_file=env_file,
        allow_unignored=False,
        surface="research",
        provider="openai",
        env_key="OPENAI_RESEARCH_API_KEY",
        model="gpt-4.1-mini",
        api_base=None,
        key=None,
    )

    text = env_file.read_text(encoding="utf-8")
    assert "# BEGIN LLM AUTH SURFACE research api-key" in text
    assert "# provider=openai" in text
    assert "# env=OPENAI_RESEARCH_API_KEY" in text
    assert "OPENAI_RESEARCH_API_KEY=" in text

    surfaces = cli.discover_auth_surfaces(env_file)
    assert len(surfaces) == 1
    assert surfaces[0].name == "research"
    assert surfaces[0].auth == "api-key"
    assert surfaces[0].primary_env == "OPENAI_RESEARCH_API_KEY"


def test_add_api_key_refuses_unignored_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    (tmp_path / ".git").mkdir()
    env_file = tmp_path / ".env"

    with pytest.raises(SystemExit, match="is not ignored by git"):
        cli.append_api_key_surface(
            env_file=env_file,
            allow_unignored=False,
            surface="research",
            provider="openai",
            env_key="OPENAI_RESEARCH_API_KEY",
            model=None,
            api_base=None,
            key=None,
        )


def test_existing_env_permissions_must_not_be_too_open(tmp_path: Path) -> None:
    env_file = ignored_env_repo(tmp_path)
    env_file.write_text("", encoding="utf-8")
    env_file.chmod(0o644)

    with pytest.raises(SystemExit, match="permissions 644 are too open"):
        cli.validate_env_store(env_file)


def test_existing_env_must_be_ignored(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    env_file.chmod(0o600)

    with pytest.raises(SystemExit, match="is not ignored by git"):
        cli.validate_env_store(env_file)


def test_env_must_not_be_tracked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = ignored_env_repo(tmp_path)
    monkeypatch.setattr(cli, "is_vcs_tracked", lambda repo, rel_path: True)
    monkeypatch.setattr(cli, "has_vcs_history", lambda repo, rel_path: False)

    with pytest.raises(SystemExit, match="is tracked by git"):
        cli.validate_env_store(env_file, require_ignored=True)


def test_env_must_not_appear_in_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = ignored_env_repo(tmp_path)
    monkeypatch.setattr(cli, "is_vcs_tracked", lambda repo, rel_path: False)
    monkeypatch.setattr(cli, "has_vcs_history", lambda repo, rel_path: True)

    with pytest.raises(SystemExit, match="appears in git commit history"):
        cli.validate_env_store(env_file, require_ignored=True)


def test_sapling_repo_uses_supported_ignore_files(tmp_path: Path) -> None:
    (tmp_path / ".sl").mkdir()
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")

    assert cli.is_ignored_root_env(tmp_path / ".env") is True


def test_status_reports_api_key_without_revealing_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    env_file = ignored_env_repo(tmp_path)
    env_file.write_text(
        "\n".join(
            [
                "# BEGIN LLM AUTH SURFACE research api-key",
                "# surface=research",
                "# provider=openai",
                "# auth=api-key",
                "# env=OPENAI_RESEARCH_API_KEY",
                "OPENAI_RESEARCH_API_KEY=secret-value",
                "# END LLM AUTH SURFACE research api-key",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_RESEARCH_API_KEY", "secret-value")

    surfaces = cli.discover_auth_surfaces(env_file)
    assert cli.status(None, surfaces) == 0

    output = capsys.readouterr().out
    assert "secret-value" not in output
    data = json.loads(output)
    assert data["research"]["api_key"] is True
    assert data["research"]["env"] == "OPENAI_RESEARCH_API_KEY"


def test_api_key_env_name_is_provider_surface_template() -> None:
    assert cli.api_key_env_name("research", "openai") == "OPENAI_RESEARCH_API_KEY"
    assert cli.api_key_env_name("team.eval", "open-router") == "OPEN_ROUTER_TEAM_EVAL_API_KEY"


def test_poll_for_authorization_code_delegates_and_restores_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    class AuthModule:
        DEVICE_CODE_TIMEOUT_SECONDS = 900

    class FakeAuthenticator:
        seen_timeout: float | None = None

        def _poll_for_authorization_code(self, device_code):
            self.seen_timeout = AuthModule.DEVICE_CODE_TIMEOUT_SECONDS
            assert device_code == {"device_auth_id": "device", "user_code": "CODE"}
            return {
                "authorization_code": "auth",
                "code_challenge": "challenge",
                "code_verifier": "verifier",
            }

    original_import = __import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "litellm.llms.chatgpt" and fromlist == ("authenticator",):
            return type("ChatGPTPackage", (), {"authenticator": AuthModule})
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", fake_import)
    authenticator = FakeAuthenticator()

    result = cli.poll_for_authorization_code(
        authenticator,
        {"device_auth_id": "device", "user_code": "CODE"},
        12.5,
    )

    assert result["authorization_code"] == "auth"
    assert authenticator.seen_timeout == 12.5
    assert AuthModule.DEVICE_CODE_TIMEOUT_SECONDS == 900


def test_project_metadata_keeps_litellm_optional() -> None:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert "litellm" not in data["project"].get("dependencies", [])
    assert "litellm" in data["project"]["optional-dependencies"]["chatgpt"]


def test_login_chatgpt_requests_litellm_extra_when_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "configure_litellm_chatgpt_env", lambda *args: None)

    def missing_litellm(*args) -> None:
        raise ImportError("No module named 'litellm'")

    monkeypatch.setattr(cli, "install_env_chatgpt_auth", missing_litellm)

    with pytest.raises(SystemExit) as exc:
        cli.login_chatgpt(
            tmp_path / ".env",
            cli.default_chatgpt_surface(),
            tmp_path / ".litellm-chatgpt",
            "auth.json",
            180,
        )

    message = str(exc.value)
    assert "LiteLLM ChatGPT provider is not installed" in message
    assert "python -m pip install 'llm-auth[chatgpt]'" in message


def test_openai_api_key_surface_validates_key_without_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    surface = cli.AuthSurface(
        name="research",
        auth="api-key",
        metadata={"provider": "openai", "env": "OPENAI_RESEARCH_API_KEY"},
        env_keys=("OPENAI_RESEARCH_API_KEY",),
    )
    monkeypatch.setenv("OPENAI_RESEARCH_API_KEY", "corrupted-key")

    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            401,
            "Unauthorized",
            hdrs={},
            fp=io.BytesIO(b'{"error":{"message":"Incorrect API key: corrupted-key"}}'),
        )

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)

    results = cli.run_api_key_subtests(
        surface,
        cli.TestContext(
            env_file=Path(".env"),
            token_dir=Path(".litellm-chatgpt"),
            auth_file_name="auth.json",
            selected_model=None,
            surface_models={},
            timeout=1,
            verbose=False,
            show_raw_error=False,
        ),
    )

    assert [result.name for result in results] == ["api-key", "openai-api-key-auth"]
    assert results[0].passed is True
    assert results[1].passed is False
    assert "HTTP 401" in results[1].detail
    assert "corrupted-key" not in results[1].detail


def test_chatgpt_completion_does_not_mislabel_provider_import_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    surface = cli.default_chatgpt_surface()
    monkeypatch.setenv(cli.CHATGPT_AUTH_JSON_ENV, json.dumps({"access_token": "access-token"}))
    monkeypatch.setattr(cli, "install_env_chatgpt_auth", lambda *args: None)

    fake_litellm = types.SimpleNamespace(suppress_debug_info=False)

    def completion(**kwargs):
        raise ImportError("provider exploded")

    fake_litellm.completion = completion
    monkeypatch.setitem(sys.modules, "litellm", fake_litellm)

    result = cli.chatgpt_completion_subtest(
        surface,
        tmp_path / ".env",
        tmp_path / ".litellm-chatgpt",
        "auth.json",
        "chatgpt/gpt-5.4-mini",
        1,
        True,
        False,
    )

    assert result.passed is False
    assert "provider exploded" in result.detail
    assert "install it with" not in result.detail


def test_response_output_text_handles_responses_shape() -> None:
    assert (
        cli.response_output_text(
            {
                "output": [
                    {
                        "content": [
                            {"text": "1"},
                        ]
                    }
                ]
            }
        )
        == "1"
    )


def test_main_add_api_key_uses_env_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    ignored_env_repo(tmp_path)

    assert (
        cli.main(
            [
                "--env-file",
                ".env",
                "add-api-key",
                "research",
                "openai",
                "--model",
                "gpt-4.1-mini",
            ]
        )
        == 0
    )
    assert "OPENAI_RESEARCH_API_KEY=" in (tmp_path / ".env").read_text(encoding="utf-8")
