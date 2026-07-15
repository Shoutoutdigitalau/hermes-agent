"""Regression tests for chat startup preserving a profile's custom SOUL.md."""

from __future__ import annotations

import hashlib

import pytest


def test_chat_with_preloaded_worker_skill_preserves_custom_soul(
    monkeypatch,
    tmp_path,
    capsys,
):
    import cli as cli_mod
    from hermes_cli.cli_agent_setup_mixin import CLIAgentSetupMixin

    profile_home = tmp_path / ".hermes" / "profiles" / "web-dev"
    profile_home.mkdir(parents=True)
    soul_path = profile_home / "SOUL.md"
    custom_soul = "CUSTOM WEB DEV SOUL\nDo not replace this identity.\n"
    soul_path.write_text(custom_soul, encoding="utf-8")
    before_hash = hashlib.sha256(soul_path.read_bytes()).hexdigest()

    monkeypatch.setenv("HERMES_HOME", str(profile_home))
    monkeypatch.setattr(cli_mod, "_run_cleanup", lambda **_kwargs: None)
    monkeypatch.setattr(cli_mod, "_finalize_single_query", lambda _cli: None)
    monkeypatch.setattr(cli_mod.HermesCLI, "_claim_active_session", lambda *a, **k: True)
    monkeypatch.setattr(cli_mod.HermesCLI, "_install_tool_callbacks", lambda self: None)
    monkeypatch.setattr(cli_mod.HermesCLI, "_ensure_tirith_security", lambda self: None)
    monkeypatch.setattr(
        cli_mod,
        "build_preloaded_skills_prompt",
        lambda skills, task_id=None: (
            "Loaded worker skill: kanban-worker",
            ["kanban-worker"],
            [],
        ),
    )
    monkeypatch.setattr(
        CLIAgentSetupMixin,
        "_ensure_runtime_credentials",
        lambda self: True,
    )
    monkeypatch.setattr(
        "hermes_cli.mcp_startup.wait_for_mcp_discovery",
        lambda: None,
    )

    captured = {}

    class FakeAIAgent:
        def __init__(self, **kwargs):
            self.session_id = kwargs["session_id"]
            self.quiet_mode = kwargs.get("quiet_mode", False)
            self.suppress_status_output = False
            self.stream_delta_callback = kwargs.get("stream_delta_callback")
            self.tool_gen_callback = kwargs.get("tool_gen_callback")
            self.ephemeral_system_prompt = kwargs.get("ephemeral_system_prompt")
            self.skip_context_files = kwargs.get("skip_context_files", False)

        def run_conversation(self, user_message, conversation_history):
            from agent.prompt_builder import load_soul_md
            from hermes_cli.config import ensure_hermes_home

            ensure_hermes_home()
            captured["soul_prompt"] = load_soul_md()
            captured["ephemeral_system_prompt"] = self.ephemeral_system_prompt
            captured["user_message"] = user_message
            return {"final_response": "ok"}

    monkeypatch.setattr(cli_mod, "AIAgent", lambda **kwargs: FakeAIAgent(**kwargs))

    with pytest.raises(SystemExit) as exc_info:
        cli_mod.main(
            query="check the kanban worker lane",
            skills=["kanban-worker"],
            provider="local",
            model="test-model",
            base_url="http://127.0.0.1:9/v1",
            api_key="test-key",
            quiet=True,
            toolsets="safe",
        )

    assert exc_info.value.code == 0
    assert hashlib.sha256(soul_path.read_bytes()).hexdigest() == before_hash
    assert soul_path.read_text(encoding="utf-8") == custom_soul
    assert captured["soul_prompt"] == custom_soul.strip()
    assert "Loaded worker skill: kanban-worker" in captured["ephemeral_system_prompt"]
    assert captured["user_message"] == "check the kanban worker lane"
    assert "ok" in capsys.readouterr().out
