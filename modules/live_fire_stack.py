"""Compose-stack runtime for live-fire v2.

WHY THIS EXISTS
`live_fire_verifier.DockerRuntime` builds ONE Dockerfile context per side and
runs ONE container.  A live-fire bundle is a multi-service compose stack
(its own `docker-compose.yml`), so "does the service still answer a normal
request the way the original did" -- the operator's SLA constraint, and the
whole job of the v2 validator agent -- could not be asked at all.  This module
is that missing capability, and nothing else in v2 can be validated without it.

FOUR FACTS ABOUT THE ENVIRONMENT SHAPED EVERY DECISION HERE.

1.  The worker has no PyYAML.  So compose is used as its OWN parser:
    `docker compose config --format json` returns the fully resolved model --
    env interpolation done, `depends_on` normalised, build contexts made
    absolute -- and json is in the standard library.  Guessing at compose
    semantics with a hand-rolled YAML pass would be strictly worse.  The model
    is written back out as JSON, which compose reads because JSON is a subset
    of YAML.  The round trip must preserve `additional_contexts`
    byte-for-byte for any service that uses it: when a bundle's build pulls
    source through that key, it is how PATCHED SOURCE reaches the image.  Lose
    it and the stack validates the base while reporting on the patch -- a
    silent wrong answer.

2.  `/usr/local/bin/docker` in the worker is `worker/docker_memguard.sh`, whose
    scope is deliberately `run` and `create` only.  `compose up` talks to the
    daemon's API directly, so it walks straight past that guard: no memory cap,
    no CPU cap, no job label.  An uncapped sibling container is what took the
    WSL2 VM out of memory on 2026-08-01 (job 0ddd62708d39).  The caps and the
    label are therefore injected DECLARATIVELY into the generated stack file --
    `mem_limit`, `cpus`, `pids_limit` per service -- which is both testable and
    not reliant on a shim that cannot see this call path.

3.  `modules/_common.reap_job_siblings` sweeps containers and networks by
    label, but NOT volumes and NOT images.  Every service times N blueteam
    stacks leaks faster than anything this project has seen, so teardown is
    `down -v --rmi local --remove-orphans` in a `finally`, and the label rides
    along anyway so a hard-killed job is still reapable.

4.  A bundle need not declare a `healthcheck`, and short-form
    `depends_on` is start-ORDER only -- compose resolves it to
    `condition: service_started`.  `up -d` returning therefore means nothing;
    a web service is up the instant its database's container starts, not
    when the database has finished its first-run init.  Readiness is this
    module's own problem, and `wait_ready` is it.

THE COLLISIONS, AND WHY EACH ONE IS STRIPPED.
Two stacks of one bundle cannot coexist without the transform below.  A
resolved model can pin any of these:

    name: <bundle>                  -> project name, replaced by `-p`
    container_name: <fixed>         -> a FIXED container name
    ports: <host>:<target>          -> a fixed host port
    image: <svc>:latest             -> a fixed TAG on a built service.  Two
                                       stacks building different sources
                                       both tag it and clobber each other,
                                       so a validator reports on an image
                                       it did not build.
    networks / volumes: name: ...   -> a fixed name, resolved eagerly by
                                       config or written into the bundle

Networks and volumes need only their resolved `name` key DELETED: compose then
auto-names them `<project>_<key>`, which is isolation for free.
"""

from __future__ import annotations

import base64
import difflib
import gzip
import json
import re

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from modules.live_fire_verifier import (
    CommandResult,
    CommandRunner,
    DockerCommandError,
    SubprocessRunner,
)

COMPOSE_FILENAME = "docker-compose.yml"
STACK_FILENAME = "stack.yml"
JOB_LABEL = "hextech_ctf_tool_job_id"
STACK_LABEL = "hextech_ctf_tool_lf_stack"
PROBE_IMAGE = "python:3.12-slim"

# A compose project name reaches Docker as a prefix for container, network,
# volume and image names, so it is constrained the same way those are.
_SAFE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{0,54}$")
_SAFE_MEMORY = re.compile(r"^[1-9][0-9]*[kKmMgG]$")

# argv, not stdin: SubprocessRunner has no stdin channel and adding one to
# reach a single probe would widen a boundary that exists to be narrow.
# MAX_ARG_STRLEN is 128KiB on Linux; stay well under it and fail loudly rather
# than let execve truncate a corpus into a silently shorter one.
_MAX_SPEC_BYTES = 64 * 1024


# `live_fire_verifier`'s shared runner caps command output at 256KiB, which is
# right for a verifier reading a handful of probe lines and WRONG here: one
# corpus capture can outgrow it before compression, and the cap silently cut
# a JSON document short at exactly byte 262144 on the first real run. It
# surfaced as a JSONDecodeError with no hint of its cause. Two changes follow
# from that: a budget sized for a corpus, and a payload that says so when it
# has been cut.
PROBE_OUTPUT_LIMIT = 64 * 1024 * 1024
_TRUNCATION_MARK = "[output truncated]"
_PAYLOAD_MARK = "LFGZ:"


class ProbeRunner(SubprocessRunner):
    """SubprocessRunner with a corpus-sized output budget."""

    @staticmethod
    def _read_output(stream: Any) -> str:
        stream.seek(0)
        payload = stream.read(PROBE_OUTPUT_LIMIT + 1)
        truncated = len(payload) > PROBE_OUTPUT_LIMIT
        text = payload[:PROBE_OUTPUT_LIMIT].decode("utf-8", errors="replace")
        if truncated:
            text += "\n" + _TRUNCATION_MARK
        return text


def _decode_payload(text: str, phase: str) -> Any:
    """Read a probe's gzipped payload, refusing a truncated one by name.

    The bodies are gzipped inside the container because HTML compresses about
    tenfold, so the wire cost of a corpus stops scaling with how chatty the
    pages are. The marker lets a stray warning line from Docker precede the
    payload without breaking the parse.
    """

    if _TRUNCATION_MARK in text:
        raise StackError(
            f"{phase} output was truncated at {PROBE_OUTPUT_LIMIT} bytes; "
            "split the corpus rather than trusting a half-read capture"
        )
    index = text.find(_PAYLOAD_MARK)
    if index < 0:
        raise StackError(f"{phase} produced no payload: {text[:400]!r}")
    blob = text[index + len(_PAYLOAD_MARK) :].strip()
    try:
        raw = gzip.decompress(base64.b64decode(blob)).decode("utf-8")
        return json.loads(raw)
    except Exception as exc:
        raise StackError(f"{phase} payload could not be read: {exc}") from exc


class StackError(ValueError):
    """A stack could not be described, isolated, or brought up."""


@dataclass(frozen=True)
class StackLimits:
    """Per-SERVICE caps, plus the stack-level timeouts.

    `memory` and `cpus` are per service and a bundle runs several of them, so
    the defaults are a share of the stack budget, not a single
    container's comfort.  mysql is the one that actually wants headroom.
    """

    memory: str = "1g"
    cpus: float = 2.0
    pids: int = 512
    build_timeout_s: float = 1800.0
    up_timeout_s: float = 600.0
    ready_timeout_s: float = 300.0
    probe_timeout_s: float = 60.0
    down_timeout_s: float = 300.0
    ready_streak: int = 3
    ready_interval_s: float = 2.0

    def __post_init__(self) -> None:
        if not _SAFE_MEMORY.match(self.memory):
            raise StackError(f"memory must look like 512m or 2g, got {self.memory!r}")
        if self.cpus <= 0:
            raise StackError("cpus must be positive")
        if self.pids <= 0:
            raise StackError("pids must be positive")
        if self.ready_streak < 1:
            raise StackError("ready_streak must be at least 1")
        for name in (
            "build_timeout_s",
            "up_timeout_s",
            "ready_timeout_s",
            "probe_timeout_s",
            "down_timeout_s",
        ):
            if getattr(self, name) <= 0:
                raise StackError(f"{name} must be positive")

    def as_dict(self) -> dict[str, Any]:
        return {
            "memory": self.memory,
            "cpus": self.cpus,
            "pids": self.pids,
            "ready_streak": self.ready_streak,
        }


@dataclass(frozen=True)
class Entrypoint:
    """A front door the bundle published, recorded as the transform strips it.

    The published host port is discarded -- that is the collision -- but the
    TARGET port is what a probe inside the network dials, and which services
    were published is the only statement the bundle makes about where its
    front doors are.  Losing that would leave the corpus with nothing to aim at.
    """

    service: str
    port: int
    network: str

    def url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"http://{self.service}:{self.port}{path}"


@dataclass(frozen=True)
class CorpusRequest:
    """One benign request.  `name` is the key the comparator joins on.

    Requests sharing a `session` name share a cookie jar and run in the order
    given, so a login can be followed by the pages it unlocks. That is not a
    nicety: pages behind a login are where patches tend to land. Without a
    jar the validator cannot check the SLA on the endpoints most likely to
    be patched, which is the majority of the question it exists to answer.

    An empty `session` means an isolated jar for that request alone, so an
    anonymous page cannot silently inherit a login from earlier in the list.

    `serves` names the bundle-relative file this request returns VERBATIM, and
    it exists to answer one question: is a difference explained by the patch
    itself? A blueteam fix that edits a static file the corpus fetches
    directly (a script or a stylesheet) makes that request differ on
    every single run -- not because the service broke but because the fix
    landed. Without this, every static-file fix is rejected by its own
    validator and never reaches the repo agent.

    The claim is CHECKED, not trusted: `live_fire_validator` compares the base
    response to the file on disk and discards a `serves` whose bytes do not
    match. A rendered page cannot claim to be a file, so the escape hatch
    cannot be widened by an agent that would like a pass.
    """

    name: str
    service: str
    port: int
    path: str
    method: str = "GET"
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str = ""
    session: str = ""
    serves: str = ""

    def as_spec(self) -> dict[str, Any]:
        # `serves` deliberately does NOT travel to the container: it is a claim
        # about the bundle, not an instruction to the probe.
        return {
            "name": self.name,
            "service": self.service,
            "port": self.port,
            "path": self.path,
            "method": self.method.upper(),
            "headers": dict(self.headers),
            "body": self.body,
            "session": self.session,
        }


@dataclass(frozen=True)
class CapturedResponse:
    name: str
    status: int
    headers: Mapping[str, str]
    body: str
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "headers": dict(self.headers),
            "body": self.body,
            "error": self.error,
        }


def _require(phase: str, result: CommandResult) -> CommandResult:
    if result.exit_code != 0 or result.timed_out:
        raise DockerCommandError(phase, result)
    return result


def _guard_project(project: str) -> str:
    if not _SAFE_PROJECT.match(project):
        raise StackError(
            "compose project name must be lowercase alphanumeric with _ or -, "
            f"1-55 chars; got {project!r}"
        )
    return project


def _guard_bind_mounts(model: Mapping[str, Any]) -> None:
    """Reject a service-level bind mount rather than pass it through.

    `DockerRuntime._guard_no_bind_mount_args` exists because a build context is
    read by the WORKER's Docker CLI and shipped as a tar stream, while a bind
    SOURCE is resolved by the HOST daemon -- so `/data/jobs/...` in a bind
    silently crosses a namespace and mounts whatever happens to sit at that
    path on the host.  This module does not go through DockerRuntime, so the
    same guard has to exist here.  A bundle that uses only named volumes
    trips nothing here; the point is that one with a host bind cannot cross
    that boundary quietly.
    """

    for service, spec in sorted((model.get("services") or {}).items()):
        for mount in spec.get("volumes") or []:
            if isinstance(mount, str):
                # Short form `./src:/dst` is a bind whenever the source is a
                # path rather than a volume name.
                source = mount.split(":", 1)[0]
                if "/" in source or source.startswith("."):
                    raise StackError(
                        f"service {service!r} declares a bind mount ({mount!r}); "
                        "live-fire stacks forbid host binds"
                    )
                continue
            if str(mount.get("type", "volume")).lower() == "bind":
                raise StackError(
                    f"service {service!r} declares a bind mount "
                    f"(source {mount.get('source')!r}); "
                    "live-fire stacks forbid host binds"
                )


def compose_argv(
    *,
    stack_file: Path,
    project: str,
    project_directory: Path | None = None,
    docker_argv: Sequence[str] = ("docker",),
) -> list[str]:
    argv = [*docker_argv, "compose", "-f", str(stack_file), "-p", project]
    if project_directory is not None:
        argv.extend(("--project-directory", str(project_directory)))
    return argv


def resolve_model(
    bundle_dir: Path,
    *,
    runner: CommandRunner | None = None,
    docker_argv: Sequence[str] = ("docker",),
    timeout_s: float = 120.0,
    compose_filename: str = COMPOSE_FILENAME,
) -> dict[str, Any]:
    """Ask compose to describe the bundle, fully resolved, as JSON."""

    runner = runner or SubprocessRunner()
    path = Path(bundle_dir) / compose_filename
    if not path.is_file():
        raise StackError(f"no {compose_filename} under {bundle_dir}")
    argv = [
        *docker_argv,
        "compose",
        "-f",
        str(path),
        "--project-directory",
        str(bundle_dir),
        "config",
        "--format",
        "json",
    ]
    result = _require("compose-config", runner.run(argv, timeout_s))
    try:
        model = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise StackError(f"compose config did not return JSON: {exc}") from exc
    if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
        raise StackError("compose config returned no services")
    return model


def isolate_model(
    model: Mapping[str, Any],
    *,
    job_id: str,
    project: str,
    limits: StackLimits,
) -> tuple[dict[str, Any], list[Entrypoint]]:
    """Strip every fixed name and inject the caps and the job label.

    Returns the stack model plus the entrypoints recovered from the `ports`
    entries the transform removes.  Pure: no Docker, no filesystem.
    """

    _guard_project(project)
    _guard_bind_mounts(model)
    out = json.loads(json.dumps(model))  # deep copy through plain JSON types
    out.pop("name", None)

    labels = {JOB_LABEL: job_id, STACK_LABEL: project}
    entrypoints: list[Entrypoint] = []

    services = out.get("services") or {}
    if not services:
        raise StackError("model has no services to isolate")
    for name, spec in sorted(services.items()):
        # THE NAME IS STRIPPED BUT NOT LOST. Two stacks cannot both own one
        # fixed container name, so it has to go -- but a bundle's own code
        # may CALL ITS SIBLING SERVICES BY THAT NAME.
        #
        # Deleting it outright would leave such a stack resolving nothing, and
        # because base and patched stacks would fail identically, the corpus
        # comparison alone could not catch it.
        #
        # Re-added as a NETWORK ALIAS instead: intra-stack DNS resolves the
        # original name, while the container itself is named by the project
        # and two stacks never collide.
        original_name = str(spec.pop("container_name", "") or "").strip()
        if original_name:
            nets = spec.get("networks")
            if isinstance(nets, dict) and nets:
                for net_name, net_spec in list(nets.items()):
                    entry = dict(net_spec or {})
                    aliases = list(entry.get("aliases") or [])
                    if original_name not in aliases:
                        aliases.append(original_name)
                    entry["aliases"] = aliases
                    nets[net_name] = entry
        if spec.get("build"):
            # Only safe to drop when compose can regenerate a tag from the
            # project; a pull-only service has nothing else to name.
            spec.pop("image", None)
        for port in spec.pop("ports", None) or []:
            target = port.get("target") if isinstance(port, dict) else None
            if target is None:
                continue
            entrypoints.append(
                Entrypoint(service=name, port=int(target), network=_first_network(spec))
            )
        spec["restart"] = "no"
        spec["mem_limit"] = limits.memory
        spec["memswap_limit"] = limits.memory
        spec["cpus"] = limits.cpus
        spec["pids_limit"] = limits.pids
        merged = dict(spec.get("labels") or {})
        merged.update(labels)
        spec["labels"] = merged

    for section in ("networks", "volumes"):
        for _, spec in sorted((out.get(section) or {}).items()):
            spec.pop("name", None)
            merged = dict(spec.get("labels") or {})
            merged.update(labels)
            spec["labels"] = merged

    entrypoints.sort(key=lambda e: (e.service, e.port))
    return out, entrypoints


def _first_network(spec: Mapping[str, Any]) -> str:
    nets = spec.get("networks")
    if isinstance(nets, dict) and nets:
        return sorted(nets)[0]
    if isinstance(nets, list) and nets:
        return sorted(str(n) for n in nets)[0]
    return "default"


def write_stack_file(model: Mapping[str, Any], path: Path) -> Path:
    """Write the model where compose will read it back.

    JSON, deliberately: it is a subset of YAML, compose parses it, and it keeps
    PyYAML out of the worker image.
    """

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(model, indent=2, sort_keys=True), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

# Runs INSIDE the probe container.  urllib, not curl: the image is
# python:3.12-slim (already cached on this host -- it is the worker's own base)
# so no pull is needed and no extra package has to exist.  Redirects are NOT
# followed on purpose: following one hides a 302->200 change, and a status
# change is exactly the kind of SLA break this module is here to catch.
# Bodies are decoded latin-1 so arbitrary bytes survive the JSON round trip
# losslessly -- a bundle's responses need not be UTF-8.
_PROBE_SCRIPT = r'''
import base64, gzip, http.cookiejar, json, sys, urllib.request, urllib.error
spec = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
timeout = float(sys.argv[2])
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
_jars = {}
def _opener(session):
    # A named session keeps its jar across requests; an unnamed one gets a
    # fresh jar so an anonymous page cannot inherit a login by accident.
    if session and session in _jars:
        return _jars[session]
    jar = http.cookiejar.CookieJar()
    built = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar), _NoRedirect)
    built._lf_jar = jar
    if session:
        _jars[session] = built
    return built
out = []
for r in spec:
    url = "http://%s:%d%s" % (r["service"], r["port"], r["path"])
    data = r["body"].encode("utf-8") if r["body"] else None
    req = urllib.request.Request(url, data=data, method=r["method"])
    for k, v in r["headers"].items():
        req.add_header(k, v)
    status, headers, body, err = -1, {}, "", ""
    opener = _opener(r.get("session") or "")
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read().decode("latin-1")
    except urllib.error.HTTPError as e:
        status = e.code
        headers = {k.lower(): v for k, v in e.headers.items()}
        body = e.read().decode("latin-1")
        # A login that answers 302 + Set-Cookie is the ordinary shape, and
        # _NoRedirect turns that 302 into this exception. Extract explicitly
        # rather than trusting processor ordering to have done it already;
        # a CookieJar ignores a duplicate.
        try:
            jar = getattr(opener, "_lf_jar", None)
            if jar is not None:
                jar.extract_cookies(e, req)
        except Exception:
            pass
    except Exception as e:
        err = "%s: %s" % (type(e).__name__, e)
    out.append({"name": r["name"], "status": status, "headers": headers,
                "body": body, "error": err})
raw = json.dumps(out).encode("utf-8")
sys.stdout.write("LFGZ:" + base64.b64encode(gzip.compress(raw, 6)).decode("ascii"))
'''


# A second, tiny probe: can this service's port be CONNECTED to at all.
# HTTP readiness cannot answer that question for a database, and a database
# is where the readiness problem actually lives.
_TCP_SCRIPT = r'''
import base64, gzip, json, socket, sys
targets = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))
timeout = float(sys.argv[2])
out = []
for t in targets:
    try:
        conn = socket.create_connection((t["host"], int(t["port"])), timeout)
        conn.close()
        out.append({"host": t["host"], "port": t["port"], "ok": True, "error": ""})
    except Exception as e:
        out.append({"host": t["host"], "port": t["port"], "ok": False,
                    "error": "%s: %s" % (type(e).__name__, e)})
raw = json.dumps(out).encode("utf-8")
sys.stdout.write("LFGZ:" + base64.b64encode(gzip.compress(raw, 6)).decode("ascii"))
'''


class ComposeStack:
    """One isolated instance of the bundle's compose stack."""

    def __init__(
        self,
        *,
        bundle_dir: Path,
        job_id: str,
        project: str,
        work_dir: Path,
        limits: StackLimits | None = None,
        runner: CommandRunner | None = None,
        docker_argv: Sequence[str] = ("docker",),
        probe_image: str = PROBE_IMAGE,
    ):
        self.bundle_dir = Path(bundle_dir)
        self.job_id = job_id
        self.project = _guard_project(project)
        self.work_dir = Path(work_dir)
        self.limits = limits or StackLimits()
        self.runner = runner or ProbeRunner()
        self.docker_argv = tuple(docker_argv)
        self.probe_image = probe_image
        self.stack_file = self.work_dir / STACK_FILENAME
        self.entrypoints: list[Entrypoint] = []
        self._up = False

    # -- lifecycle ---------------------------------------------------------

    def _compose(self, args: Sequence[str], timeout_s: float) -> CommandResult:
        argv = compose_argv(
            stack_file=self.stack_file,
            project=self.project,
            project_directory=self.bundle_dir,
            docker_argv=self.docker_argv,
        )
        return self.runner.run([*argv, *args], timeout_s)

    def prepare(self) -> list[Entrypoint]:
        """Resolve, isolate and write the stack file.  No containers yet."""

        model = resolve_model(
            self.bundle_dir,
            runner=self.runner,
            docker_argv=self.docker_argv,
        )
        isolated, entrypoints = isolate_model(
            model, job_id=self.job_id, project=self.project, limits=self.limits
        )
        write_stack_file(isolated, self.stack_file)
        self.entrypoints = entrypoints
        if not entrypoints:
            raise StackError(
                "bundle publishes no ports, so it declares no front door to "
                "capture a corpus against"
            )
        return entrypoints

    def up(self) -> None:
        if not self.stack_file.is_file():
            self.prepare()
        # Build first and separately so a build failure is attributable to the
        # build rather than surfacing as an opaque `up` error.
        _require("compose-build", self._compose(("build",), self.limits.build_timeout_s))
        self._up = True
        _require(
            "compose-up",
            self._compose(("up", "-d", "--no-build"), self.limits.up_timeout_s),
        )

    def down(self) -> CommandResult:
        """Teardown.  Never raises -- a failed cleanup must not fail a job.

        `-v` and `--rmi local` are not optional here: `reap_job_siblings`
        sweeps containers and networks by label but neither volumes nor
        images, so those two are this method's responsibility alone.
        """

        self._up = False
        return self._compose(
            ("down", "-v", "--rmi", "local", "--remove-orphans", "-t", "10"),
            self.limits.down_timeout_s,
        )

    def __enter__(self) -> "ComposeStack":
        self.up()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.down()

    # -- reachability ------------------------------------------------------

    def network_for(self, entrypoint: Entrypoint) -> str:
        """The name compose gave the network, derived from the project.

        Deleting the resolved `name` key in `isolate_model` is what makes this
        derivable at all; with the bundle's eager `kweb_*` names it would be
        a fixed string shared by every stack.
        """

        return f"{self.project}_{entrypoint.network}"

    def probe(
        self, requests: Sequence[CorpusRequest], *, network: str
    ) -> list[CapturedResponse]:
        """Run every request from one throwaway container on the stack network.

        One container for the whole batch, not one per request: container start
        dominates an HTTP round trip by an order of magnitude, and a corpus is
        tens of requests.
        """

        if not requests:
            return []
        spec = json.dumps([r.as_spec() for r in requests], sort_keys=True)
        blob = base64.b64encode(spec.encode("utf-8")).decode("ascii")
        if len(blob) > _MAX_SPEC_BYTES:
            raise StackError(
                f"corpus spec is {len(blob)} bytes, over the {_MAX_SPEC_BYTES} "
                "argv budget; split the corpus"
            )
        argv = self._probe_argv(
            _PROBE_SCRIPT, blob, str(self.limits.probe_timeout_s), network
        )
        budget = self.limits.probe_timeout_s * len(requests) + 60.0
        result = _require("probe", self.runner.run(argv, budget))
        raw = _decode_payload(result.stdout, "probe")
        return [
            CapturedResponse(
                name=str(item["name"]),
                status=int(item["status"]),
                headers=dict(item.get("headers") or {}),
                body=str(item.get("body") or ""),
                error=str(item.get("error") or ""),
            )
            for item in raw
        ]

    def _probe_argv(
        self, script: str, blob: str, timeout_arg: str, network: str
    ) -> list[str]:
        """The one place a probe container is described.

        Shared by the HTTP and TCP probes so the network join and the two
        labels cannot drift apart between them -- an unlabelled probe is
        invisible to reap_job_siblings, and there is no reason for two
        spellings of the same container to exist.
        """

        return [
            *self.docker_argv,
            "run",
            "--rm",
            "--network",
            network,
            "--label",
            f"{JOB_LABEL}={self.job_id}",
            "--label",
            f"{STACK_LABEL}={self.project}",
            self.probe_image,
            "python",
            "-c",
            script,
            blob,
            timeout_arg,
        ]

    def exposed_ports(self) -> dict[str, list[int]]:
        """What each running service declares it listens on.

        Read from the image's own EXPOSE rather than from the compose file:
        a database service often publishes nothing and names no port there,
        which is precisely why an HTTP-only readiness gate cannot see it.
        """

        listed = self._compose(("ps", "-q"), self.limits.probe_timeout_s)
        ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        out: dict[str, list[int]] = {}
        for cid in ids:
            argv = [
                *self.docker_argv,
                "inspect",
                "--format",
                '{{index .Config.Labels "com.docker.compose.service"}}'
                "|{{range $p, $v := .Config.ExposedPorts}}{{$p}} {{end}}",
                cid,
            ]
            result = self.runner.run(argv, self.limits.probe_timeout_s)
            if result.exit_code != 0 or "|" not in result.stdout:
                continue
            service, ports = result.stdout.strip().split("|", 1)
            service = service.strip()
            if not service:
                continue
            found = []
            for spec in ports.split():
                number, _, proto = spec.partition("/")
                if proto and proto != "tcp":
                    continue
                try:
                    found.append(int(number))
                except ValueError:
                    continue
            if found:
                out[service] = sorted(set(found))
        return out

    def probe_tcp(
        self, targets: Sequence[tuple[str, int]], *, network: str
    ) -> list[tuple[str, int, bool, str]]:
        if not targets:
            return []
        spec = json.dumps(
            [{"host": host, "port": port} for host, port in targets], sort_keys=True
        )
        blob = base64.b64encode(spec.encode("utf-8")).decode("ascii")
        argv = self._probe_argv(_TCP_SCRIPT, blob, "5", network)
        result = _require("tcp-probe", self.runner.run(argv, 120.0))
        raw = _decode_payload(result.stdout, "tcp-probe")
        return [
            (str(i["host"]), int(i["port"]), bool(i["ok"]), str(i.get("error") or ""))
            for i in raw
        ]

    def wait_tcp(self, *, network: str) -> None:
        """Every service's own port must accept a connection before anything else.

        THIS is the gate that sees a seeding database, and HTTP stability is
        not a substitute for it. A DB-backed list page can answer a steady
        200 for the whole pre-seed window, because an empty list renders
        consistently, so waiting for the HTML to stop changing can pass inside
        the window and the baseline gets built against an empty database.

        The official mysql image starts a TEMPORARY server with
        `--skip-networking` to run docker-entrypoint-initdb.d, and only execs
        the real mysqld -- the one that listens on TCP -- once those scripts
        have finished. So "can I open 3306" is not a proxy for "is the seed
        done": it is the same event.
        """

        ports = self.exposed_ports()
        targets = [(svc, port) for svc, nums in sorted(ports.items()) for port in nums]
        if not targets:
            return
        deadline = time.monotonic() + self.limits.ready_timeout_s
        last = "no tcp probe ran"
        while time.monotonic() < deadline:
            try:
                seen = self.probe_tcp(targets, network=network)
            except (DockerCommandError, StackError) as exc:
                last = str(exc)
                time.sleep(self.limits.ready_interval_s)
                continue
            closed = [(h, p, e) for h, p, ok, e in seen if not ok]
            if not closed:
                return
            last = ", ".join(f"{h}:{p}" for h, p, _ in closed[:4])
            time.sleep(self.limits.ready_interval_s)
        raise StackError(
            f"stack {self.project} still had closed ports after "
            f"{self.limits.ready_timeout_s}s: {last}"
        )

    def wait_ready(self, requests: Sequence[CorpusRequest], *, network: str) -> None:
        """Poll until the front door answers the SAME WAY `ready_streak` times.

        Short-form `depends_on` resolves to `service_started` (only a long-form
        `condition: service_healthy` against a declared healthcheck waits), so
        `up -d` returning tells us only that processes were launched -- the
        web tier is "up" while the database is still running its first-boot
        init.

        A 2xx IS NOT READINESS: a DB-backed list page can answer 200 before
        docker-entrypoint-initdb.d has seeded the database and 200 with a much
        longer body after it, and during that seeding window a login can fail
        with the ordinary wrong-credentials page, indistinguishable from a
        genuinely wrong password.

        The compounding failure is what makes this the gate's whole job: TWO
        base captures taken inside that window AGREE WITH EACH OTHER, so
        calibration marks the corpus perfectly stable and the SLA is then
        checked, in good faith, against a half-initialised system.

        So the signal is stability, not success: status AND body length must
        repeat unchanged across consecutive polls. Length rather than content
        because a nonce or a session id changes on literally every request
        while the page's LENGTH is fixed, and a state transition like the one
        above moves the length noticeably.

        Give it at least one DB-backed page. A static front page is exactly
        the thing that looks identical on both sides of the transition.
        """

        self.wait_tcp(network=network)
        if not requests:
            return
        deadline = time.monotonic() + self.limits.ready_timeout_s
        streak = 0
        last = "no probe ran"
        previous: dict[str, tuple[int, int]] | None = None
        while time.monotonic() < deadline:
            try:
                seen = self.probe(requests, network=network)
            except (DockerCommandError, StackError) as exc:
                streak = 0
                previous = None
                last = str(exc)
                time.sleep(self.limits.ready_interval_s)
                continue
            bad = [r for r in seen if r.error or r.status < 200 or r.status >= 500]
            if bad:
                streak = 0
                previous = None
                first = bad[0]
                last = f"{first.name}: status={first.status} error={first.error}"
            else:
                shape = {r.name: (r.status, len(r.body)) for r in seen}
                if previous is not None and shape == previous:
                    streak += 1
                    if streak >= self.limits.ready_streak:
                        return
                else:
                    if previous is not None:
                        moved = sorted(
                            n for n in shape if previous.get(n) != shape[n]
                        )
                        last = f"still changing: {', '.join(moved)}"
                    streak = 0
                previous = shape
            time.sleep(self.limits.ready_interval_s)
        raise StackError(
            f"stack {self.project} never settled within "
            f"{self.limits.ready_timeout_s}s; last: {last}"
        )

    def inspect_caps(self) -> dict[str, dict[str, Any]]:
        """Read the cgroup values Docker actually applied, per container.

        A YAML key one believes compose honours is not the same evidence as a
        cgroup that exists, and the failure mode is a dead VM rather than a
        wrong answer.  `compose up` bypasses worker/docker_memguard.sh
        entirely, so this is the only place the caps get confirmed.
        """

        listed = self._compose(("ps", "-q"), self.limits.probe_timeout_s)
        ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        out: dict[str, dict[str, Any]] = {}
        for cid in ids:
            argv = [
                *self.docker_argv,
                "inspect",
                "--format",
                "{{.Name}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}"
                "|{{.HostConfig.PidsLimit}}",
                cid,
            ]
            result = self.runner.run(argv, self.limits.probe_timeout_s)
            if result.exit_code != 0:
                continue
            parts = result.stdout.strip().split("|")
            if len(parts) != 4:
                continue
            name, memory, nano_cpus, pids = parts
            out[name.lstrip("/")] = {
                "memory": int(memory or 0),
                "nano_cpus": int(nano_cpus or 0),
                "pids_limit": int(pids or 0),
            }
        return out


# --------------------------------------------------------------------------
# The comparator
# --------------------------------------------------------------------------
#
# "정상 서비스 응답은 원본과 동일하게 유지되어야 함" cannot be byte equality.
# Date headers, session cookies, CSRF tokens, MySQL autoincrement ids and any
# rendered timestamp differ on every single run, so a naive diff reports the
# entire corpus as broken.  Hand-picking which fields to ignore is the other
# failure: the field quietly excluded is eventually the field that mattered.
#
# So the normaliser is CALIBRATED FROM THE BUNDLE, not guessed.  The base
# corpus is captured twice, against two independently built base stacks, and
# anything that differs BETWEEN THE TWO BASE RUNS is nondeterministic by
# construction and excluded from the patched comparison.  It self-tunes, it
# generalises to the next bundle, and it comes with a free sanity signal: if
# two base runs disagree in the BODY of a read-only endpoint, the stack itself
# is unstable and that would otherwise have been chased as a patch regression.
#
# The floor below does not contradict that.  Empirical calibration can only ADD
# to the ignore set, never remove from it; the floor exists for one specific
# flake -- if both base captures land in the same second, `date` matches, looks
# stable, and the patched run minutes later fails on it.  A residual risk of
# the same shape remains for second-granularity timestamps rendered into a
# body; two independently BUILT stacks put minutes between the captures, which
# is the mitigation.
_VOLATILE_HEADER_FLOOR = frozenset(
    {
        "date",
        "set-cookie",
        "etag",
        "last-modified",
        "expires",
        "age",
        "x-request-id",
        "x-runtime",
        "x-powered-by",
        "keep-alive",
    }
)

# Derived from the body, so comparing it as well would report one cause twice.
# The body check is authoritative for anything content-length could reveal.
_DERIVED_HEADERS = frozenset({"content-length"})


@dataclass(frozen=True)
class RequestBaseline:
    """What two base runs agreed on, and precisely where they did not.

    The body is modelled as a SPINE -- the lines both base runs produced, in
    order -- with a GAP before each spine line and one after the last. A gap
    whose CONTENT differed between the two base runs is nondeterministic and
    its content is unconstrained; but if both runs put the same NUMBER of
    lines there, that count is still an oracle, which is what stops a patch
    hiding an added banner inside the slot where a session id lives.
    """

    name: str
    status: int
    stable_status: bool
    headers: Mapping[str, str]
    volatile_headers: frozenset[str]
    spine: tuple[str, ...]
    stable_gaps: tuple[tuple[str, ...], ...]
    volatile_gaps: frozenset[int]
    gap_widths: tuple[int, ...]
    transport_error: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "stable_status": self.stable_status,
            "volatile_headers": sorted(self.volatile_headers),
            "spine_lines": len(self.spine),
            "volatile_gaps": sorted(self.volatile_gaps),
            "transport_error": self.transport_error,
        }


@dataclass(frozen=True)
class SlaFinding:
    name: str
    kind: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "kind": self.kind, "detail": self.detail}


@dataclass(frozen=True)
class SlaVerdict:
    """The answer, plus how much of the corpus it actually rests on.

    `checked` is not decoration. Every unstable request is skipped before it
    can produce a finding, so a verdict built only from skipped requests would
    be `ok=True` with no evidence behind it -- "everything wobbled, therefore
    the SLA held". `min_checked` is the floor that stops that, and it is
    enforced HERE rather than left to each caller, because the caller that
    forgets is exactly the one that ships a green light for nothing.
    """

    ok: bool
    checked: int
    total: int
    findings: tuple[SlaFinding, ...]
    unstable: tuple[str, ...]
    broken: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checked": self.checked,
            "total": self.total,
            "findings": [f.as_dict() for f in self.findings],
            "unstable": list(self.unstable),
            "broken": list(self.broken),
        }


def _lines(body: str) -> list[str]:
    return body.splitlines()


def _spine(a: Sequence[str], b: Sequence[str]) -> tuple[str, ...]:
    """The lines both base runs produced, in order: the stable skeleton.

    autojunk is off deliberately.  SequenceMatcher's heuristic treats a line
    appearing in over 1% of a long sequence as junk, and HTML is full of
    repeated `  </div>` lines -- exactly the structural lines whose loss means
    the page broke.
    """

    matcher = difflib.SequenceMatcher(None, list(a), list(b), autojunk=False)
    out: list[str] = []
    for block in matcher.get_matching_blocks():
        out.extend(list(a)[block.a : block.a + block.size])
    return tuple(out)


def _align(
    spine: Sequence[str], observed: Sequence[str]
) -> tuple[list[tuple[str, ...]], list[bool]]:
    """Lay a body against the spine: what fills each gap, and what is missing.

    Returns `len(spine) + 1` gaps -- gap *i* is whatever sits before spine
    line *i*, and the last is the tail -- plus a per-spine-line flag saying
    whether the observed body still contains it, in order. A spine line that
    went missing is the signal that matters most: escaping a field, dropping a
    row, or rewording a status message each REMOVE the original line, and that
    is exactly the SLA break the attack server's benign payload sees.
    """

    matcher = difflib.SequenceMatcher(None, list(spine), list(observed), autojunk=False)
    gaps: list[list[str]] = [[] for _ in range(len(spine) + 1)]
    matched = [False] * len(spine)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                matched[i1 + offset] = True
        elif tag in ("insert", "replace"):
            # `replace` is both at once: the spine lines in i1:i2 are absent
            # (their flags simply stay False) and observed j1:j2 arrived in
            # their place, which belongs to the gap that opens at i1.
            gaps[i1].extend(list(observed)[j1:j2])
    return [tuple(g) for g in gaps], matched


def _gap_detail(before: Sequence[str], after: Sequence[str]) -> str:
    added = [line for line in after if line not in before]
    if added:
        return added[0].strip()[:200]
    return f"{len(before)} line(s) here became {len(after)}"


def calibrate(
    *captures: Sequence[CapturedResponse],
) -> dict[str, RequestBaseline]:
    """Learn what is nondeterministic from two or more base captures.

    TWO IS THE MINIMUM AND IT IS NOT ALWAYS ENOUGH, measured rather than
    supposed. A clock-derived field coarser than the gap between two base
    captures reads the same in both; calibration learns it as fixed, and a
    later patched capture is blamed for the clock.

    Volatility has two sources needing different exposure: per-REQUEST (nonces,
    session ids, autoincrement keys) shows between any two captures at all,
    while per-CLOCK needs captures separated by more than the field's
    granularity. A third capture taken across a minute boundary closes the
    second, and every capture is compared, so a field only has to vary ONCE to
    be excluded forever.
    """

    if len(captures) < 2:
        raise StackError("calibration needs at least two base captures")
    heads = list(captures[0])
    others = [{r.name: r for r in rest} for rest in captures[1:]]
    out: dict[str, RequestBaseline] = {}
    for first in heads:
        rest: list[CapturedResponse] = []
        for index, lookup in enumerate(others):
            found = lookup.get(first.name)
            if found is None:
                raise StackError(
                    f"request {first.name!r} is in the first base capture but "
                    f"not capture {index + 2}; every capture must use the same "
                    "corpus"
                )
            rest.append(found)
        seen = [first, *rest]

        volatile = set(_VOLATILE_HEADER_FLOOR) | set(_DERIVED_HEADERS)
        keys: set[str] = set()
        for response in seen:
            keys |= set(response.headers)
        for key in keys:
            values = {response.headers.get(key) for response in seen}
            if len(values) > 1:
                volatile.add(key)

        line_sets = [_lines(response.body) for response in seen]
        spine = tuple(line_sets[0])
        for lines in line_sets[1:]:
            spine = _spine(spine, lines)
        aligned = [_align(spine, lines)[0] for lines in line_sets]
        volatile_gaps = {
            i
            for i in range(len(spine) + 1)
            if len({gaps[i] for gaps in aligned}) > 1
        }
        # -1 means the base runs did not even agree on how many lines sit in
        # this slot, so nothing about it can be asserted. Where they DID agree
        # on the count, the count survives as an oracle even though the
        # content does not.
        widths = tuple(
            len(aligned[0][i])
            if len({len(gaps[i]) for gaps in aligned}) == 1
            else -1
            for i in range(len(spine) + 1)
        )
        out[first.name] = RequestBaseline(
            name=first.name,
            status=first.status,
            stable_status=len({r.status for r in seen}) == 1,
            headers=dict(first.headers),
            volatile_headers=frozenset(volatile),
            spine=spine,
            stable_gaps=tuple(aligned[0]),
            volatile_gaps=frozenset(volatile_gaps),
            gap_widths=widths,
            transport_error=any(bool(r.error) for r in seen),
        )
    return out


def compare(
    baseline: Mapping[str, RequestBaseline],
    patched: Sequence[CapturedResponse],
    *,
    strict_extras: bool = True,
    min_checked: int = 1,
) -> SlaVerdict:
    """Judge a patched capture against the calibrated base.

    `strict_extras` defaults to true because the operator's constraint is that
    the normal response stay the SAME, and an added line is a change the
    attack-server's SLA payload can see.  It is a separate flag because an
    added line is the one deviation a reviewer may knowingly accept.

    `min_checked` is the coverage floor described on `SlaVerdict`.
    """

    findings: list[SlaFinding] = []
    unstable: list[str] = []
    broken: list[str] = []
    seen = {r.name: r for r in patched}

    for name in sorted(baseline):
        base = baseline[name]
        if base.transport_error:
            # NOT the same thing as a wobbling body. The base capture never
            # reached the service at all, so this is a broken corpus entry or
            # a stack that did not come up -- a setup fault to fix, not a
            # nondeterminism to tolerate. Tolerating it would let a corpus
            # rot away request by request while every verdict stayed green.
            broken.append(name)
            findings.append(
                SlaFinding(
                    name,
                    "corpus-broken",
                    "the base capture never reached the service",
                )
            )
            continue
        if not base.stable_status:
            unstable.append(f"{name}: base status differed between the two runs")
            continue
        observed = seen.get(name)
        if observed is None:
            findings.append(
                SlaFinding(name, "request-missing", "no patched capture for this request")
            )
            continue
        if observed.error:
            findings.append(SlaFinding(name, "transport-error", observed.error))
            continue
        if observed.status != base.status:
            findings.append(
                SlaFinding(
                    name,
                    "status",
                    f"base {base.status} -> patched {observed.status}",
                )
            )
        for key in sorted(set(base.headers) | set(observed.headers)):
            if key in base.volatile_headers:
                continue
            before = base.headers.get(key)
            after = observed.headers.get(key)
            if before == after:
                continue
            if before is None:
                findings.append(SlaFinding(name, "header-added", f"{key}: {after!r}"))
            elif after is None:
                findings.append(SlaFinding(name, "header-missing", f"{key}: was {before!r}"))
            else:
                findings.append(
                    SlaFinding(name, "header-changed", f"{key}: {before!r} -> {after!r}")
                )
        observed_lines = _lines(observed.body)
        gaps, matched = _align(base.spine, observed_lines)
        for index, present in enumerate(matched):
            if not present:
                findings.append(
                    SlaFinding(
                        name, "body-missing-line", base.spine[index].strip()[:200]
                    )
                )
        if strict_extras:
            for index in range(len(base.spine) + 1):
                if index not in base.volatile_gaps:
                    if gaps[index] != base.stable_gaps[index]:
                        findings.append(
                            SlaFinding(
                                name,
                                "body-extra-line",
                                _gap_detail(base.stable_gaps[index], gaps[index]),
                            )
                        )
                    continue
                # The base itself varied here, so the content is not an
                # oracle -- but the WIDTH still is whenever both runs agreed
                # on it. Without this, a banner inserted next to a session id
                # would be indistinguishable from the session id changing.
                width = base.gap_widths[index]
                if width >= 0 and len(gaps[index]) != width:
                    findings.append(
                        SlaFinding(
                            name,
                            "body-extra-line" if len(gaps[index]) > width
                            else "body-missing-line",
                            f"a nondeterministic slot held {width} line(s) in "
                            f"both base runs and {len(gaps[index])} here",
                        )
                    )

    checked = len(baseline) - len(unstable) - len(broken)
    if checked < min_checked:
        findings.append(
            SlaFinding(
                "",
                "coverage",
                f"only {checked} of {len(baseline)} corpus requests were "
                f"comparable; at least {min_checked} must be, or the verdict "
                "rests on nothing",
            )
        )
    return SlaVerdict(
        ok=not findings,
        checked=checked,
        total=len(baseline),
        findings=tuple(findings),
        unstable=tuple(unstable),
        broken=tuple(broken),
    )
