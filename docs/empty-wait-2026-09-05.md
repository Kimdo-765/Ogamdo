# EMPTY WAIT — 근본 원인 확정과 수정안 보류 (2026-09-05)

**상태: 검증 완료, 구현 보류.** 오퍼레이터 판단으로 기록만 남긴다.

`31d64cb6f5b1`은 42.3분에 성공했지만 그중 **13~16분(31~38%)** 을 빈 `wait`에
썼다. 플래그는 `+37:26`에 잡혔다 — 빈 wait가 없었다면 25분 안팎에 끝났을 job이다.

---

## 1. `wait`의 정체

thinking도, 서브에이전트 과정도 아니다. **진짜 도구 호출**이다.

`31d64cb6f5b1`의 `gpt-events.jsonl`:
```
('wait','wait')            19건   tool_started
('tool_completed','wait')  19건
  input  : {}
  detail : {"sender_thread_id":"01a071c3-...","receiver_thread_ids":[],
            "prompt":null,"agents_states":{}}
```

`sender_thread_id`가 실제 값이다. codex의 스레드/에이전트 런타임이 붙어 있고
`wait`는 그 도구다.

**우리가 등록한 것이 아니다.** 이 배포는 `codex_multi_agent_v2 = False`라
`--enable`을 넘기지 않는데도 `wait`가 제공된다. codex 0.153.1의 기본 제공이다.

`--disable <FEATURE>`(= `-c features.<name>=false`)로 끌 수 있는지는 **미확정**.
A/B 실행에서 양쪽 다 `wait` 호출도 `NO_WAIT_TOOL` 응답도 나오지 않아 판별에
실패했고, 바이너리 문자열과 `--json` 스트림 어디에도 도구 목록이 없다.

---

## 2. 현재 처리 — 관찰과 대응이 분리돼 있다

**1단계 어댑터 (턴 중, `modules/codex_cli.py:1157`)**
빈 로스터를 감지해 `warning` 이벤트를 찍는다. 주석이 밝히듯 *"This line is read
by an operator"* — **오퍼레이터용 표시**다. 바로 아래에서 `tool_completed`를
평소대로 내보내므로 **모델이 받는 결과는 바뀌지 않는다.** 모델 입장에서 `wait`는
성공했고 로스터가 비었을 뿐이라, 다시 부를 이유가 있다.

**2단계 오케스트레이터 (턴 중, `modules/_common.py:10266`)**
`_empty_wait_seen(msg)`로 세기만 한다. 주석 그대로 *"Detected here, answered at
the boundary."*

**3단계 턴 경계 (`modules/_common.py:10806`)**
`EMPTY_WAIT_CORRECTION`을 주입한다. 여기서 **처음으로 모델에 도달**하며,
`corrected` 플래그 때문에 **job당 한 번뿐**이다.

---

## 3. 3단계의 실효 — 도달하면 듣지만, 필요한 곳에 못 간다

전 job 측정:
```
EMPTY WAIT 발생 job     12개
교정이 주입된 job        10개
그중 교정 후 재발 0       9개
```

문구는 유효하다. 문제는 **전달 경로**이고, 실패 형태가 둘이다.

| job | main 턴 | 빈 wait | 교정 도달 |
|---|---:|---:|---|
| `213e2708a34f` | 1 | **58** | **도달 못함** |
| `31d64cb6f5b1` | 2 | 19 | **종료 8초 전** |
| `48fadce3dde7` | 40 | 21 | 도달, 이후 **42회 재발** |

`31d64cb6f5b1` 타임라인 (턴 시작 기준):
```
+ 0:00  턴 1 시작
+ 7:04  빈 wait #1
  ...   (19회, 33분)
+40:15  빈 wait #19
+40:22  턴 1 종료 → 교정 주입 → 턴 2
+40:29  delegate
+40:30  종료
```

**"9/10 성공"은 턴이 많은 job에서만 성립하는 수치다.** 턴이 적을수록 교정이
늦고, 손실은 정확히 그런 job에서 크다. `31d64cb6f5b1`의 "재발 0"은 성공이
아니라 **관측 불가**로 읽어야 한다 — 다시 부를 턴이 8초밖에 없었다.

`48fadce3dde7`은 반대 형태다. 교정을 받고도 42회를 더 했고, 재주입이 없어
로그가 *"AFTER the correction was delivered — main is not acting on it"* 을
42번 찍기만 했다.

---

## 4. 수정안 (A) — 빈 `wait`를 도구 오류로 반환

`codex_cli.py:1157`이 **이미 감지하고 있는 그 자리**에서 반환값만 바꾼다.
새 개입을 만드는 것이 아니라 기존 파싱의 결과를 모델에게도 전달하는 것이다.
턴 경계를 기다리지 않으므로 위 두 실패를 동시에 없앤다.

### 오탐 검증 — 현재 조건에서는 0

전 job의 `gpt-events.jsonl` 335건:
```
로스터 키를 가진 응답   276건  →  전부 비어 있음
비어있지 않은 응답        0건
detail='completed'       59건  →  구형 형식(20a2b843e843, 2026-09-02), 로스터 키 없음

전 job 호출 도구  Bash 6880 / Edit 1376 / wait 676 / WebSearch 558
spawn_agent 흔적     0건
```

`wait`가 로스터를 담아 응답한 적이 **한 번도 없다.** 자식을 만들 수단이 호출된
적도 없으니 로스터가 찰 경로 자체가 없다.

기존 감지 조건은 이미 보수적이다:
```python
isinstance(_wb, dict) and ("receiver_thread_ids" in _wb or "agents_states" in _wb)
and not (_wb.get("receiver_thread_ids") or _wb.get("agents_states"))
```
로스터 키가 **실제로 있을 때만** 판정하므로 `detail='completed'` 59건은 자동
제외된다. (A)가 이 자리를 그대로 쓰면 형식이 다른 응답을 오류로 만들 위험은
없다.

### 그러나 조건이 바뀌면 오탐이 생긴다

1. **`codex_multi_agent_v2`를 켜면** — codex가 실제 서브에이전트를 붙일 수 있고,
   그때는 *자식이 모두 끝난 직후의 빈 로스터*가 정상이다.
2. **codex가 `spawn_agent`를 제공하면** — 현재 0건은 이 버전의 사실이지 영구
   보장이 아니다. CLI 업그레이드로 바뀔 수 있다.

### 그래서 구현한다면 무조건이 아니라 게이팅

```
빈 로스터를 오류로 변환  ←  codex_multi_agent_v2 가 OFF 일 때만
                         +  세션 중 spawn_agent 가 관측되면 자동 해제
```

근거가 대칭적이다. mav2가 OFF라는 것은 서브에이전트 기능을 광고하지 않았다는
뜻이고, 그러면 로스터는 **구조적으로** 빌 수밖에 없다. ON이면 그 보장이
사라지므로 현행(경고 + 턴 경계 교정)으로 돌아가면 된다.

---

## 5. 재개할 때 확인할 것

- `codex_multi_agent_v2` 설정값 — 이 문서 작성 시점 `False`
- `wait` 응답 중 비어있지 않은 것이 생겼는지 (위 335건 집계를 다시 돌릴 것)
- codex CLI 버전 — 이 문서 작성 시점 `0.153.1`
- `--disable`로 끌 feature 이름을 알아냈는지 (미확정 상태로 남음)
