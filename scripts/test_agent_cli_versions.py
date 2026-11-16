#!/usr/bin/env python3
"""배포가 Claude/Codex/Grok CLI 를 최신 안정판으로 올리는 경로를 지킨다.

이 스위트가 막는 회귀는 구체적이다. 이 기능 이전에는
`api/Dockerfile` 과 `worker/Dockerfile` 이 `@anthropic-ai/claude-code@2.1.158`
을 **리터럴로** 박아 두었고, 그 결과 배포를 아무리 해도 Claude 는 그 버전에
머물렀다(도입 시점 실측: 최신은 2.1.258 — 100 버전 뒤처져 있었다).
Codex 는 빌드 인자였지만 기본값이 `0.147.0` 으로 고정이었고,
Grok 은 이미지에 아예 없어 호스트 `~/.grok` 마운트에 의존했다.

따라서 검사는 셋이다:
  1. Dockerfile 이 CLI 버전을 리터럴로 박지 않는다
  2. compose 가 api 와 **모든** worker 빌드에 세 인자를 넘긴다
  3. start.sh 가 빌드 **이전에** 버전을 해석한다

네트워크가 필요한 검사는 OGAMDO_CLI_NETWORK_TEST=1 일 때만 돈다.
"""
import os
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z._-]*)?$")
DOCKERFILES = ("api/Dockerfile", "worker/Dockerfile")


class AgentCliVersionTests(unittest.TestCase):
    def test_dockerfiles_do_not_pin_a_literal_cli_version(self) -> None:
        """리터럴이 하나라도 있으면 그 CLI 는 배포로 갱신되지 않는다."""
        offenders: list[str] = []
        for name in DOCKERFILES:
            for lineno, line in enumerate(
                (ROOT / name).read_text(encoding="utf-8").splitlines(), 1
            ):
                if re.search(r"claude-code@[0-9]", line) \
                        or re.search(r"codex@[0-9]", line):
                    offenders.append(f"{name}:{lineno}: {line.strip()}")
                # 기본값이 고정 버전이면 인자를 안 넘겼을 때 조용히 낡는다
                if re.match(r"\s*ARG\s+(CLAUDE|CODEX|GROK)_CLI_VERSION=[0-9]", line):
                    offenders.append(f"{name}:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [], "고정 버전이 남아 있다:\n" + "\n".join(offenders))

    def test_dockerfiles_use_the_shared_installer(self) -> None:
        for name in DOCKERFILES:
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("install-agent-clis.sh", text, f"{name} 이 공용 설치기를 안 쓴다")
            for arg in ("CLAUDE_CLI_VERSION", "CODEX_CLI_VERSION", "GROK_CLI_VERSION"):
                self.assertRegex(text, rf"ARG\s+{arg}", f"{name} 에 {arg} 인자가 없다")

    def test_compose_passes_versions_to_api_and_every_worker(self) -> None:
        import yaml

        spec = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        services = spec.get("services") or {}
        targets = [
            name for name, body in services.items()
            if isinstance(body, dict) and isinstance(body.get("build"), dict)
            and str((body["build"] or {}).get("dockerfile", "")).startswith(
                ("api/", "worker/"))
        ]
        self.assertTrue(targets, "api/worker 빌드를 가진 서비스를 못 찾았다")
        for name in targets:
            args = (services[name]["build"] or {}).get("args") or {}
            for key in ("CLAUDE_CLI_VERSION", "CODEX_CLI_VERSION", "GROK_CLI_VERSION"):
                self.assertIn(key, args, f"{name} 빌드에 {key} 가 없다")

    def test_start_resolves_versions_before_building(self) -> None:
        text = (ROOT / "start.sh").read_text(encoding="utf-8")
        resolve_at = text.find("resolve-agent-cli-versions.sh")
        build_at = text.find('up -d --build')
        self.assertNotEqual(resolve_at, -1, "start.sh 가 버전을 해석하지 않는다")
        self.assertNotEqual(build_at, -1, "start.sh 의 빌드 호출을 못 찾았다")
        self.assertLess(resolve_at, build_at, "해석이 빌드보다 뒤에 있다 — 인자가 비어 나간다")

    def test_installer_verifies_the_command_contracts(self) -> None:
        """버전만 맞추고 계약을 안 보면 upstream 메이저가 런타임에서 터진다."""
        text = (ROOT / "scripts/install-agent-clis.sh").read_text(encoding="utf-8")
        for probe in ("--output-format", "--json", "stdio"):
            self.assertIn(probe, text, f"설치기가 {probe} 계약을 검증하지 않는다")

    def test_node_major_is_new_enough_for_the_clis_we_pin(self) -> None:
        """베이스 이미지의 Node가 우리가 고정하는 CLI를 감당해야 한다.

        `install-agent-clis.sh` 는 npm 을 engine-strict 로 돌린다. 그래서
        불일치는 조용히 넘어가지 않고 **빌드를 실패시킨다** — 그게 맞는
        동작이다. 실제로 터졌다: 리졸버가 claude-code 를
        2.1.158 → 2.1.258 로 올리는 순간 그 패키지의
        `engines.node ">=22.0.0"` 을 넘어섰는데 두 Dockerfile 은 여전히
        Node 20 을 설치하고 있어서, 13개 이미지 빌드가 한꺼번에
        EBADENGINE 으로 죽었다.

        고칠 곳은 핀이 아니라 베이스 이미지다. 두 Dockerfile 이 같은
        메이저를 쓰는지, 그리고 그게 현재 하한(22) 이상인지 고정한다.
        """
        majors = {}
        for name in DOCKERFILES:
            text = (ROOT / name).read_text(encoding="utf-8")
            m = re.search(r"deb\.nodesource\.com/setup_(\d+)\.x", text)
            self.assertIsNotNone(m, f"{name} 이 nodesource 로 node 를 안 깐다")
            majors[name] = int(m.group(1))
        self.assertEqual(len(set(majors.values())), 1,
                         f"api 와 worker 의 node 메이저가 다르다: {majors}")
        self.assertGreaterEqual(
            min(majors.values()), 22,
            "claude-code 는 node>=22 를 요구한다 — setup_NN.x 를 올려라")

    def test_installer_explains_a_node_mismatch_itself(self) -> None:
        """npm 의 EBADENGINE 벽 대신, 어느 층을 고쳐야 하는지 말해야 한다."""
        text = (ROOT / "scripts/install-agent-clis.sh").read_text(encoding="utf-8")
        self.assertIn("engines.node", text, "설치기가 엔진 요구사항을 안 읽는다")
        self.assertIn("FIX THE BASE IMAGE", text,
                      "실패 메시지가 '핀이 아니라 베이스 이미지'라고 말하지 않는다")
        self.assertIn("exit 3", text, "불일치가 빌드를 멈추지 않는다")

    @unittest.skipUnless(
        os.environ.get("OGAMDO_CLI_NETWORK_TEST") == "1",
        "네트워크 검사는 OGAMDO_CLI_NETWORK_TEST=1 일 때만",
    )
    def test_resolver_returns_three_valid_versions(self) -> None:
        out = subprocess.run(
            ["bash", str(ROOT / "scripts/resolve-agent-cli-versions.sh")],
            capture_output=True, text=True, timeout=180, cwd=ROOT,
        )
        self.assertEqual(out.returncode, 0, out.stderr[-400:])
        parts = out.stdout.split()
        self.assertEqual(len(parts), 3, f"stdout 이 3개가 아니다: {out.stdout!r}")
        for value in parts:
            self.assertRegex(value, SEMVER.pattern)


if __name__ == "__main__":
    unittest.main(verbosity=2)
