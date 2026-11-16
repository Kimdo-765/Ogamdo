#!/usr/bin/env python3
"""Focused offline regressions for the kernel/Daybreak ultra path."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if importlib.util.find_spec("docker") is None:
    docker_stub = types.ModuleType("docker")
    docker_stub.from_env = lambda *args, **kwargs: None
    docker_stub.DockerClient = type("DockerClient", (), {})
    docker_errors = types.ModuleType("docker.errors")
    for error_name in (
        "APIError", "DockerException", "ImageNotFound", "NotFound",
        "NullResource",
    ):
        setattr(docker_errors, error_name, type(error_name, (Exception,), {}))
    docker_types = types.ModuleType("docker.types")
    docker_types.Mount = type("Mount", (), {"__init__": lambda self, **kwargs: None})
    docker_stub.errors = docker_errors
    docker_stub.types = docker_types
    sys.modules.update({
        "docker": docker_stub,
        "docker.errors": docker_errors,
        "docker.types": docker_types,
    })

if importlib.util.find_spec("claude_agent_sdk") is None:
    sdk_stub = types.ModuleType("claude_agent_sdk")
    for class_name in (
        "AgentDefinition", "AssistantMessage", "ClaudeAgentOptions",
        "ClaudeSDKClient", "HookMatcher",
        "ResultMessage", "SystemMessage", "TextBlock", "ToolResultBlock",
        "ToolUseBlock", "UserMessage",
    ):
        setattr(sdk_stub, class_name, type(class_name, (), {}))
    async def sdk_query(*args, **kwargs):
        if False:
            yield None
    sdk_stub.query = sdk_query
    sys.modules["claude_agent_sdk"] = sdk_stub


class CodexKernelUltraTests(unittest.TestCase):
    def test_preset_ultra_survives_backend_resolution(self) -> None:
        from modules import model_presets
        from modules._common import resolve_effort

        with tempfile.TemporaryDirectory() as td:
            old_path = model_presets.MODEL_PRESETS_PATH
            model_presets.MODEL_PRESETS_PATH = Path(td) / "presets.json"
            try:
                model_presets.save_store({
                    "version": 2,
                    "providers": {
                        "gpt": {
                            "active": "ctf",
                            "presets": {
                                "ctf": {
                                    "main": "gpt-daybreak-blue-latest",
                                    "effort": "ultra",
                                }
                            },
                        }
                    },
                })
                self.assertEqual(resolve_effort(None, "gpt"), "ultra")
            finally:
                model_presets.MODEL_PRESETS_PATH = old_path

    def test_ultra_uses_native_agents_and_explicit_cli_effort(self) -> None:
        from modules.codex_cli import CodexCLIClient
        from modules.gpt_responses import GptSessionOptions

        with tempfile.TemporaryDirectory() as td:
            client = CodexCLIClient(GptSessionOptions(
                system_prompt="BASE",
                model="gpt-daybreak-blue-latest",
                cwd=td,
                effort="ultra",
                enable_tools=True,
                enable_subagents=True,
            ))
            client._codex_bin = "/usr/bin/codex"
            prompt = client._instructions("solve", resuming=False)
            command = client._command(resuming=False)

            self.assertIn("NATIVE ULTRA MODE", prompt)
            self.assertIn("`spawn_agent`", prompt)
            self.assertNotIn("`spawn_agent` DOES NOT WORK HERE", prompt)
            self.assertNotIn(".scratch/delegate.json", prompt)
            self.assertNotIn("QEMU", prompt)
            self.assertNotIn("exploit.py", prompt)
            self.assertNotIn("FLAG_CANDIDATE", prompt)
            self.assertIn('model_reasoning_effort="ultra"', command)
            self.assertIn("features.multi_agent_v2=true", command)
            role_files = list((Path(td) / "tmp" / "codex-agents").glob("*.toml"))
            self.assertEqual(len(role_files), 4)
            self.assertTrue(all(
                'model_reasoning_effort = "ultra"' in p.read_text()
                for p in role_files
            ))

    def test_non_ultra_keeps_legacy_delegate_contract(self) -> None:
        from modules.codex_cli import (
            CODEX_NATIVE_ULTRA_ADDENDUM,
            CODEX_TOOL_ADDENDUM,
            CodexCLIClient,
        )
        from modules.gpt_responses import GptSessionOptions

        with tempfile.TemporaryDirectory() as td:
            client = CodexCLIClient(GptSessionOptions(
                system_prompt="BASE",
                model="gpt-5.6-sol",
                cwd=td,
                effort="high",
                enable_tools=True,
                enable_subagents=True,
            ))
            prompt = client._instructions("solve", resuming=False)
            self.assertIn(".scratch/delegate.json", prompt)
            for transport_prompt in (
                CODEX_TOOL_ADDENDUM, CODEX_NATIVE_ULTRA_ADDENDUM
            ):
                for domain_term in (
                    "QEMU", "exploit.py", "solver.py", "report.md",
                    "FLAG_CANDIDATE", "KASLR",
                ):
                    self.assertNotIn(domain_term, transport_prompt)

    def test_kernel_prompts_are_compact_and_not_userspace_remote_only(self) -> None:
        from modules.pwn.prompts import (
            KERNEL_SYSTEM_PROMPT,
            SYSTEM_PROMPT,
            build_kernel_pre_recon_prompt,
            build_user_prompt,
            kernel_local_e2e_available,
        )

        user = build_user_prompt(
            None,
            "example.invalid:31337",
            "kernel pwn",
            True,
            chal_unpacked=True,
            kernel_challenge=True,
            local_e2e_available=True,
        )
        recon = build_kernel_pre_recon_prompt(
            None, "example.invalid:31337"
        )

        self.assertLess(len(KERNEL_SYSTEM_PROMPT), 5000)
        self.assertLess(len(KERNEL_SYSTEM_PROMPT), len(SYSTEM_PROMPT) // 10)
        self.assertNotIn("native Codex", KERNEL_SYSTEM_PROMPT)
        self.assertNotIn("Binary: NOT PROVIDED", user)
        self.assertNotIn("%p %p %p", user)
        self.assertNotIn("./.chal-libs/", user)
        self.assertIn("REMOTE_READY", user)
        self.assertIn("INDEPENDENT FULL-CHAIN ROUTES", recon)
        self.assertNotIn("HOOKS_ALIVE", recon)
        no_local = build_user_prompt(
            None,
            "example.invalid:31337",
            "different kernel pwn",
            True,
            chal_unpacked=True,
            kernel_challenge=True,
            local_e2e_available=False,
        )
        self.assertIn("strongest faithful local validation", no_local)
        self.assertNotIn("locally successful", no_local)
        self.assertIn("REMOTE_READY", no_local)

        with tempfile.TemporaryDirectory() as td:
            chal = Path(td) / "chal"
            chal.mkdir()
            (chal / "vuln.ko").write_bytes(b"module only")
            self.assertFalse(kernel_local_e2e_available(td))
            (chal / "bzImage").write_bytes(b"kernel")
            (chal / "rootfs.cpio").write_bytes(b"rootfs")
            self.assertFalse(kernel_local_e2e_available(td))
            (chal / "flag").write_text("local stand-in")
            self.assertFalse(kernel_local_e2e_available(td))
            (chal / "run.sh").write_text(
                "qemu-system-x86_64 -kernel ./bzImage -initrd ./rootfs.cpio\n"
            )
            self.assertTrue(kernel_local_e2e_available(td))
            self.assertFalse(kernel_local_e2e_available(td, explicit=False))
            self.assertTrue(kernel_local_e2e_available(td, explicit=True))

        with tempfile.TemporaryDirectory() as td:
            chal = Path(td) / "chal"
            chal.mkdir()
            (chal / "Image").write_bytes(b"arm64 kernel")
            (chal / "run.sh").write_text(
                "qemu-system-aarch64 -machine virt -kernel ./Image\n"
            )
            self.assertTrue(kernel_local_e2e_available(td))
            from modules.pwn.analyzer import _kernel_challenge_present
            self.assertTrue(_kernel_challenge_present(Path(td)))

    def test_kernel_remote_marker_is_content_bound(self) -> None:
        from modules._common import kernel_remote_ready, kernel_ship_fingerprint

        with tempfile.TemporaryDirectory() as td:
            work = Path(td)
            scratch = work / ".scratch"
            scratch.mkdir()
            script = work / "exploit.py"
            marker = scratch / "REMOTE_READY"
            script.write_text("print('probe')\n")
            self.assertFalse(kernel_remote_ready(work, "exploit.py"))

            marker.write_text("")
            self.assertFalse(kernel_remote_ready(work, "exploit.py"))

            marker.write_text(json.dumps({
                "validation": "trust me",
                "artifacts": {
                    "exploit.py": hashlib.sha256(script.read_bytes()).hexdigest(),
                },
            }))
            self.assertFalse(kernel_remote_ready(work, "exploit.py"))

            companion = work / "exploit.c"
            companion.write_text("int main(void) { return 0; }\n")
            artifact_paths = [script, companion]

            def write_manifest() -> None:
                artifacts = {}
                for path in artifact_paths:
                    artifacts[path.name] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
                marker.write_text(json.dumps({
                    "validation": {
                        "scope": "local-e2e",
                        "command": "./run.sh",
                        "result": "privileged action confirmed",
                    },
                    "artifacts": artifacts,
                }))

            write_manifest()
            self.assertTrue(kernel_remote_ready(work, "exploit.py"))

            companion.write_text("int main(void) { return 1; }\n")
            self.assertFalse(kernel_remote_ready(work, "exploit.py"))

            write_manifest()
            self.assertTrue(kernel_remote_ready(work, "exploit.py"))

            companion.unlink()
            self.assertFalse(kernel_remote_ready(work, "exploit.py"))
            companion.write_text("int main(void) { return 1; }\n")
            write_manifest()
            self.assertTrue(kernel_remote_ready(work, "exploit.py"))

            undeclared = work / "payload.c"
            undeclared.write_text("int payload;\n")
            self.assertFalse(kernel_remote_ready(work, "exploit.py"))
            undeclared.unlink()

            opaque = work / "payload.bin"
            opaque.write_bytes(b"revision one")
            artifact_paths.append(opaque)
            write_manifest()
            before = kernel_ship_fingerprint(work, "exploit.py")
            opaque.write_bytes(b"revision two")
            after = kernel_ship_fingerprint(work, "exploit.py")
            self.assertNotEqual(before, after)
            self.assertFalse(kernel_remote_ready(work, "exploit.py"))
            write_manifest()
            self.assertTrue(kernel_remote_ready(work, "exploit.py"))

            script.write_text("print('new revision')\n")
            self.assertFalse(kernel_remote_ready(work, "exploit.py"))

    def test_kernel_remote_gate_blocks_unready_and_runs_ready(self) -> None:
        """Exercise the ship gate in the real main-session loop."""
        from modules._common import run_main_agent_session
        from modules.gpt_responses import GptSessionOptions, ResultMessage

        async def run_case(ready: bool) -> tuple[list[str], list[str], dict, object]:
            with tempfile.TemporaryDirectory() as td:
                work = Path(td)
                (work / ".scratch").mkdir()
                script = work / "exploit.py"
                script.write_text("print('complete chain')\n")
                if ready:
                    digest = hashlib.sha256(script.read_bytes()).hexdigest()
                    (work / ".scratch" / "REMOTE_READY").write_text(json.dumps({
                        "validation": {
                            "scope": "local-e2e",
                            "command": "./run.sh",
                            "result": "privileged action confirmed",
                        },
                        "artifacts": {"exploit.py": digest},
                    }))

                class FakeClient:
                    instances: list["FakeClient"] = []

                    def __init__(self, options) -> None:
                        self.options = options
                        self.queries: list[str] = []
                        self.instances.append(self)

                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, *_args):
                        return False

                    async def query(self, prompt: str) -> None:
                        self.queries.append(prompt)

                    async def receive_response(self):
                        yield ResultMessage(
                            is_error=False,
                            stop_reason="completed",
                            usage={},
                        )

                sandbox_calls: list[str] = []

                def sandbox_runner(name: str) -> dict:
                    sandbox_calls.append(name)
                    return {"sandbox_started": True, "exit_code": 0}

                def scan_flags(*_args, **kwargs) -> list[str]:
                    kwargs["provenance_out"]["tier"] = "marker"
                    return ["FLAG{integration-test}"]

                async def direct_run_sync(func, *args, **kwargs):
                    return func(*args, **kwargs)

                options = GptSessionOptions(
                    system_prompt="test",
                    model="gpt-daybreak-blue-latest",
                    cwd=str(work),
                    effort="ultra",
                )
                summary = {
                    "model": "gpt-daybreak-blue-latest",
                    "kernel_challenge": True,
                    "kernel_local_e2e": True,
                    "require_remote_ready_marker": True,
                }

                with ExitStack() as stack:
                    stack.enter_context(patch(
                        "modules.agent_provider.provider_for_job",
                        return_value="gpt",
                    ))
                    stack.enter_context(patch(
                        "modules.agent_provider.ensure_provider_ready",
                        return_value="gpt",
                    ))
                    stack.enter_context(patch(
                        "modules.agent_provider.provider_meta_fields",
                        return_value={},
                    ))
                    stack.enter_context(patch(
                        "modules.agent_provider.provider_display_name",
                        return_value="GPT",
                    ))
                    stack.enter_context(patch(
                        "modules.gpt_agent.GptAgentClient", FakeClient,
                    ))
                    stack.enter_context(patch(
                        "modules._common.read_meta",
                        return_value={"module": "pwn", "agent_provider": "gpt"},
                    ))
                    stack.enter_context(patch("modules._common.write_meta"))
                    stack.enter_context(patch("modules._common.write_why_stopped"))
                    stack.enter_context(patch(
                        "modules._common.job_dir", return_value=work,
                    ))
                    stack.enter_context(patch(
                        "modules._common.scan_job_for_flags",
                        side_effect=scan_flags,
                    ))
                    stack.enter_context(patch("modules._common.capture_session_id"))
                    stack.enter_context(patch("modules._common.agent_heartbeat"))
                    stack.enter_context(patch(
                        "modules._common.record_rate_limit_event",
                    ))
                    stack.enter_context(patch(
                        "anyio.to_thread.run_sync", side_effect=direct_run_sync,
                    ))
                    result = await run_main_agent_session(
                        "remote-ready-integration",
                        options=options,
                        initial_prompt="solve",
                        summary=summary,
                        work_dir=work,
                        artifact_names=("exploit.py",),
                        auto_run=True,
                        sandbox_runner=sandbox_runner,
                        log_fn=lambda _line: None,
                    )

                return (
                    sandbox_calls,
                    FakeClient.instances[0].queries,
                    summary,
                    result,
                )

        with self.subTest(marker="missing"):
            calls, queries, summary, result = asyncio.run(run_case(False))
            self.assertEqual(calls, [])
            self.assertEqual(len(queries), 2)
            self.assertIn("KERNEL REMOTE SHIP GATE", queries[-1])
            self.assertIn("remote execution was withheld", summary["judge_stop_reason"])
            self.assertIsNone(result)

        with self.subTest(marker="valid"):
            calls, queries, summary, result = asyncio.run(run_case(True))
            self.assertEqual(calls, ["exploit.py"])
            self.assertEqual(len(queries), 1)
            self.assertEqual(summary["sandbox_runs"], 1)
            self.assertEqual(result, {"sandbox_started": True, "exit_code": 0})

    def test_role_override_does_not_inherit_unsupported_effort(self) -> None:
        from modules.codex_cli import _write_codex_agent_configs

        parent = "gpt-daybreak-blue-latest"

        def role_model(role: str, fallback: str, provider: str) -> str:
            return "gpt-5.5" if role == "triage" else fallback

        with tempfile.TemporaryDirectory() as td, patch(
            "modules.model_presets.resolve_role_model", side_effect=role_model
        ):
            paths = _write_codex_agent_configs(td, parent, "ultra")
            self.assertIn(
                'model_reasoning_effort = "ultra"',
                paths["recon"].read_text(),
            )
            self.assertNotIn(
                "model_reasoning_effort",
                paths["triage"].read_text(),
            )

    def test_kernel_prompt_profile_change_forces_fresh_resume(self) -> None:
        from modules.pwn.analyzer import _resume_profile_status

        current = "pwn-kernel-compact-v1+codex-native-ultra-v1"
        with patch("modules.pwn.analyzer.read_meta", return_value={}):
            fresh, inherited = _resume_profile_status(
                resume_sid="old-session",
                kernel_shape=True,
                job_meta={"retry_of": "old-job"},
                current_profile=current,
            )
        self.assertTrue(fresh)
        self.assertIsNone(inherited)

        with patch(
            "modules.pwn.analyzer.read_meta",
            return_value={"agent_prompt_profile": current},
        ):
            fresh, inherited = _resume_profile_status(
                resume_sid="matching-session",
                kernel_shape=True,
                job_meta={"retry_of": "matching-job"},
                current_profile=current,
            )
        self.assertFalse(fresh)
        self.assertEqual(inherited, current)

    def test_main_options_use_job_provider_not_live_setting(self) -> None:
        from modules._common import make_main_session_options
        from modules.gpt_responses import GptSessionOptions

        with tempfile.TemporaryDirectory() as td, patch(
            "modules.agent_provider.provider_for_job", return_value="gpt"
        ), patch(
            "modules.agent_provider.active_provider", return_value="claude"
        ), patch(
            "modules._common.read_meta",
            return_value={"module": "pwn", "agent_provider": "gpt"},
        ), patch(
            "modules._common.log_line",
        ):
            options = make_main_session_options(
                job_id="provider-snapshot-test",
                work_dir=Path(td),
                model="gpt-daybreak-blue-latest",
                system_prompt="BASE",
                base_tools=["Read"],
                summary={},
                effort="ultra",
            )
            self.assertIsInstance(options, GptSessionOptions)
            self.assertEqual(options.effort, "ultra")

    def test_main_runner_checks_job_provider_not_live_setting(self) -> None:
        from modules._common import run_main_agent_session

        for provider in ("claude", "grok", "gpt"):
            with self.subTest(provider=provider), patch(
                "modules.agent_provider.provider_for_job",
                return_value=provider,
            ), patch(
                "modules.agent_provider.ensure_provider_ready",
                side_effect=RuntimeError("provider-check-stop"),
            ) as ensure:
                with self.assertRaisesRegex(RuntimeError, "provider-check-stop"):
                    asyncio.run(run_main_agent_session(
                        "snapshot-job",
                        options=object(),
                        initial_prompt="",
                        summary={},
                        work_dir=Path(tempfile.gettempdir()),
                        artifact_names=("exploit.py",),
                        auto_run=False,
                        sandbox_runner=None,
                        log_fn=lambda _line: None,
                    ))
                ensure.assert_called_once_with(provider)


if __name__ == "__main__":
    unittest.main(verbosity=2)
