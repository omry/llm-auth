import json
from pathlib import Path

import pytest

from llm_auth import cli


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
