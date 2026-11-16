# `spawn_agent` 은 동작한다 — 빈 로스터는 자식이 없다는 뜻이 아니었다 (2026-09-07)

**상태: 실측 완료, 재현 3/3.** 이 플랫폼이 2026-05 이후 쌓아온 "codex 는
서브에이전트를 못 붙인다"는 전제가 틀렸다.

## 1. 무엇을 측정했나

worker 이미지(`hextech_ctf_tool-worker:latest`)로 격리 컨테이너를 띄우고,
`codex exec --json --ignore-user-config` 에 다음을 시켰다. **프로덕션과 같은
설정** — `features.multi_agent_v2` 를 켜지 않았다.

    1. spawn_agent 를 한 번 호출해 서브에이전트를 만들어라. 그 자식의 임무는
       `echo OGAMDO_CHILD_OK > /probe/out/child.txt` 를 실행하고 DONE 이라고
       답하는 것이다.
    2. 그 자식이 끝날 때까지 기다려라.
    3. RESULT=<파일 내용> 을 출력하라.
    엄격한 규칙: echo 는 네가 직접 실행하면 안 된다. 오직 자식만 쓸 수 있다.

## 2. 결과

    exit=0
    child.txt: OGAMDO_CHILD_OK
    RESULT=OGAMDO_CHILD_OK          ← 3회 연속 동일

부모가 실행한 shell 명령은 **단 하나**, 파일을 읽는 것뿐이다:

    /bin/bash -lc "if [ -f /probe/out/child.txt ]; then cat ...; else printf 'MISSING'; fi"
    → aggregated_output: "OGAMDO_CHILD_OK\n", exit_code 0

부모는 `echo` 를 하지 않았고 파일에는 값이 있다. **자식이 실제로 돌았다.**

## 2b. 프로덕션 환경에서도 확인 (같은 날, 별도 실측)

§1 은 throwaway 컨테이너 + 복사한 CODEX_HOME 이었다. 그것만으로는 "배포된
환경에서 되는가" 에 답할 수 없어, **살아있는 워커에서 프로덕션 argv 그대로**
다시 측정했다. argv 는 실행 중이던 job 의 `/proc/<pid>/cmdline` 에서 그대로
읽었다:

    codex exec --json --ignore-user-config --ignore-rules --skip-git-repo-check
      --model gpt-daybreak-blue-latest
      --config sandbox_mode="danger-full-access"
      --config model_context_window=1050000
      --config model_auto_compact_token_limit=240000
      --config model_reasoning_effort="ultra"
      --sandbox danger-full-access -

`features.multi_agent_v2` 는 없다(설정이 False 이므로). CODEX_HOME 은 워커가
실제로 마운트한 `/root/.codex` (`auth.json`, rw) 를 그대로 썼다.

`hextech_ctf_tool-worker-3` 에서 3회:

    exit=0 | child.txt=OGAMDO_PROD_CHILD      (3/3)
    부모 shell 명령: 매번 1건, 그 파일을 읽는 명령뿐

즉 **현재 배포된 그대로의 환경에서 `spawn_agent` 이 동작한다.** 별도의 설정
변경도, v2 활성화도, 이미지 변경도 필요 없다.

## 3. 뒤집힌 두 전제

### (a) "spawn 호출 0건" 은 이벤트가 안 찍힌 것이었다

이 실행의 이벤트 스트림 9건 전체:

    thread.started 1 / turn.started 1 / agent_message 2
    collab_tool_call 2 / command_execution 2 / turn.completed 1

**`spawn_agent` 이벤트가 없다.** 자식이 확실히 돈 실행인데도 없다. 즉
`gpt-events.jsonl` 에서 spawn 을 세는 방식으로는 spawn 을 볼 수 없다.
전 job 335건에서 "spawn_agent 호출 0건" 이라던 근거는 **부재의 증거가 아니라
증거의 부재**였다.

### (b) 빈 로스터는 "자식이 없다" 가 아니다

같은 실행에서 `wait` 이 반환한 것:

    {"type": "collab_tool_call", "tool": "wait",
     "receiver_thread_ids": [], "agents_states": {}, "status": "completed"}

자식이 파일을 쓴 바로 그 실행에서 로스터가 비어 있다. 우리가 "존재할 수 없는
로스터" 라고 불러온 모양이 **자식이 있는 정상 실행에서도 나온다.**

OpenAI 문서의 v1 `wait_agent` 설명과 일치한다 — "returns empty status when
timed out". 그리고 openai/codex#24951 은 `wait_agent(timeout_ms=300000)` 이
27,017초 블록한 뒤 `{"status":{},"timed_out":true}` 를 반환한 미해결 버그를
보고한다. `timeout_ms` 가 도구 전체가 아니라 내부 대기에만 걸린다.

## 4. 왜 이렇게 오래 안 보였나 — 순환논증

`modules/codex_cli.CODEX_TOOL_ADDENDUM` 은 시스템 프롬프트 맨 앞에서
이렇게 가르친다:

    `spawn_agent`, which is not registered in this deployment.
    So do NOT call `spawn_agent`, and do NOT call `wait` at all.

그리고 그 근거로 "spawn 호출 0건" 을 든다. **부르지 말라고 가르쳐 놓고 안
부른 것을 없다는 증거로 쓴 것이다.** `features` 목록을 보면 등록 주체가
있었다:

    multi_agent      stable   true      ← v1, 기본값으로 켜져 있음
    multi_agent_v2   stable   false     ← 플랫폼이 계속 보던 쪽

플랫폼은 `codex_multi_agent_v2` 만 게이팅했고, 그건 실제로 꺼져 있다. 그러나
도구를 주는 것은 v1 이다.

## 5. 부수적으로 확인된 것

`spawn_agent` 은 **쓰기 가능한 CODEX_HOME** 을 요구한다. `:ro` 로 마운트하면
codex 가 시작조차 못 한다:

    Error: failed to initialize in-process app-server client:
    Read-only file system (os error 30)

프로덕션 워커는 `${HOST_CODEX_HOME}:/root/.codex` 를 rw 로 마운트하므로 이
조건은 이미 충족돼 있다.

## 6. 영향받는 기록

- `modules/codex_cli.CODEX_TOOL_ADDENDUM` — 핵심 주장이 사실과 다르다
- `docs/empty-wait-2026-09-05.md` — 결론이 (b) 위에 서 있다
- 커밋 `bd33eb9` — 프롬프트와 CLI 를 일치시킨 것 자체는 맞으나, **어느 쪽으로**
  일치시킬지가 다시 열린다. native 가 실제로 되므로 파일 채널을 가르치는 것이
  최선이라는 근거가 사라졌다
- 이 플랫폼이 인용해 온 유휴 시간(52/44/39/35%)의 해석

## 7. 아직 모르는 것

- 자식이 **실제로 유용한 일**을 하는가 (이 테스트는 echo 한 줄이다)
- v2 를 켜고 role 오버레이(`recon`/`debugger`/`triage`/`judge`)를 등록했을 때
  체감 성능이 파일 채널보다 나은가
- #24951 의 stall 이 이 배포에서 얼마나 자주 나는가 — 우리가 본 10/20/30/60초
  라운드 타임아웃이 그것인지

---

## 8. 프롬프트를 고친 뒤의 종단 테스트 (커밋 48cb195)

실제 `_instructions()` 가 만든 시스템 프롬프트를 그대로 `codex exec` 에 먹이고,
서로 독립인 20초짜리 하위 과제 3개 + 부모만 할 수 있는 일 1개를 시켰다.
직렬이면 60초 이상, 병렬 위임이면 25초 안팎이 나오는 설계다.

**새 프롬프트 (worker-1):**

    경과 54s, exit=0
    a.txt=Q1=alpha  b.txt=Q2=beta  c.txt=Q3=gamma  parent.txt=parent-did-this
    wait 호출 0건
    부모 직접 실행 2건 (자기 파일 쓰기, 완료 폴링)
    최종: ANSWERS=alpha,beta,gamma
    모델 서술: "launching the three independent probes concurrently and
                handling the parent-only file myself"

세 개가 동시에 돌았고, 부모는 자기 일을 했고, 답이 맞았고, `wait` 루프가 없다.

**옛 프롬프트 (같은 과제, worker-2):**

    경과 35s, exit=0
    a/b/c 전부 없음, parent.txt 만 존재
    부모가 한 일: .scratch/delegate.json 을 쓰고 턴을 끝냄
    최종 답변 없음 (ANSWERS 줄 없음)

**해석에 주의.** 옛 경로가 "실패" 한 것이 아니다. 시킨 대로 파일 채널에 요청을
남기고 턴을 끝냈고, 프로덕션이라면 오케스트레이터가 그 세 과제를 돌려 다음 턴에
답을 넣어준다. 이 격리 하네스에는 오케스트레이터가 없어서 라운드가 완결되지
않았을 뿐이다.

따라서 측정된 차이는 **"한 턴 안에서 끝나는가"** 다. 새 경로는 턴 경계 없이
54초에 완결했고, 옛 경로는 구조적으로 턴 경계 + 오케스트레이터 왕복을 요구한다.
addendum 이 "the fallback costs a turn boundary" 라고 적은 그대로다.

**아직 증명되지 않은 것.** 두 실행 모두 `wait` 을 0회 불렀다. 실제 job 에서
관측된 빈 wait 반복(23%, 27%)은 더 길고 모호한 상황에서 나오므로, 새 프롬프트의
빈-로스터 경고가 그 반복을 실제로 줄이는지는 **이 테스트로는 알 수 없다.**
실 job 여러 개로 확인해야 한다.
