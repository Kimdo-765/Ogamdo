# effort=low vs effort=ultra — worker CLI 직접 측정

측정일 2026-09-09. 모델 `gpt-daybreak-blue-latest`, codex-cli 0.153.1,
`hextech_ctf_tool-worker-*` 컨테이너에서 `codex exec` 를 직접 호출.

디스크의 job 70개는 **전부 ultra** 로 돌았고 `low` 표본이 하나도 없어 회고
비교가 불가능하다. 그래서 워커 CLI 에서 같은 입력을 effort 만 바꿔 직접 쐈다.

## 1. `ultra` 는 이 모델에서 실재하는 값이다

API 는 잘못된 값에 400 을 주면서 지원 목록을 알려준다:

    model_reasoning_effort="bogus_effort_zzz"
    -> 400 invalid_enum_value
       Supported values are: 'none','minimal','low','medium','high','xhigh','max'

`ultra` 는 그 목록에 **없는데도 400 이 나지 않고 정상 실행**된다. 통과가
우연이 아니라는 증거 두 가지:

* `ultra2` 는 같은 400 으로 거부된다 — CLI 가 문자열을 그대로 넘기고 서버가
  판정한다는 뜻이므로, `ultra` 의 통과는 서버가 인정했기 때문이다.
* 목록에 있는 `minimal` 은 오히려 이 모델에서 400 (`Unsupported value:
  'minimal'`) 이다. 즉 400 메시지의 목록은 이 모델 전용이 아니라 일반 목록이다.

이 모델이 실제로 받는 값: `none, low, medium, high, xhigh, max, ultra`.

**input 토큰 +47 은 오직 ultra 에서만 나타난다.** 동일 프롬프트 단발 호출에서
none/low/medium/high/xhigh/max 는 전부 14344~14345, ultra 만 14391~14392 로
재현된다. 서버가 ultra 를 별도로 취급한다는 직접 증거다.

## 2. 장난감 과제로는 답이 나오지 않는다 (초기 오독 기록)

첫 과제 T1(길이 8, {a,b,c}, 인접 동일 금지 + 세 글자 모두 등장 = 378):

| effort | 결과 | reasoning_tok |
|---|---|---|
| low | 756 / 762 / 630 / 510 / 510 / 756 / 486 — **7/7 오답** | 0 |
| medium | 756 오답 | 0 |
| high | 756 오답 | 0 |
| xhigh | 378 정답 | 86 |
| max | 378 정답 | 96 |
| ultra | 378 정답 ×4 | 87~133 |

여기까지만 보면 "low/medium/high 는 추론을 끈다" 로 읽힌다. **틀렸다.**
더 어려운 T2(길이 10, {a,b,c,d} = 72600)에서는 low 를 포함한 6개 effort가
전부 정답이고 low 도 reasoning_tok 122 를 썼다. 또 셸 사용을 프롬프트에서
명시하자 low 도 도구를 실행해 3/3 정답을 냈다 — 앞선 "low 는 도구를 안 쓴다"
는 관찰은 "정수만 답하라" 는 내 프롬프트가 만든 착시였다.

교훈: effort 차이는 과제 의존적이라 실전 난이도에서만 의미가 있다.

## 3. 실전 rev 배터리 (본 측정)

실제 job 에서 정답 flag 가 확정된, 원격 서버가 필요 없는 rev 문제 2개 (job 식별자·값·풀이 생략):

* **R1** — rev 문제. 정답 확정(값 생략).
* **R2** — rev 문제. 정답 확정(값 생략).

각 문제 × {low, ultra} × 3회, 동일 프롬프트·동일 2400초 타임아웃,
`sandbox_mode="danger-full-access"` 로 워커 안 빈 디렉터리에 바이너리만 복사.

(결과)

### R1 — 결정적

| effort | 정답 | 중앙 wall | 평균 명령 | 평균 출력tok | 평균 입력tok |
|---|---|---|---|---|---|
| low   | **0/3** | 291초  |  33 |  9,207 |  2.58 M |
| ultra | **3/3** | 1752초 | 157 | 63,414 | 18.99 M |

ultra 세 런 모두 실제 job 의 확정 정답(값 생략)과
문자 단위로 일치했고, 셋 다 자기가 만든 입력 프로그램으로 검증한 뒤 제출했다.

low 세 런의 결말:

* `Exhausted available approaches without recovering a reliable flag candidate.`
* `FLAG_CANDIDATE: (날조 값 생략)`  ← 형식만 맞는 날조
* `FLAG_CANDIDATE: (날조 값 생략)`        ← 형식조차 틀린 날조

### R2 — ultra 쪽 측정 무효 (프로브의 4 GiB 한계)

| effort | 정답 | 중앙 wall | 평균 명령 | 종료 사유 |
|---|---|---|---|---|
| low   | 0/3 | 155초  |  18 | 스스로 포기 (2런은 날조 후보 제출) |
| ultra | 0/2 | 2062초 | 110 | OOM 1 + 타임아웃 1, **날조 0** |

`R2_ultra_1` 은 1723초에 풀이 도중 컨테이너 4 GiB 한도에 걸려
`Killed` 로 죽었고, `R2_ultra_2` 는 139개 명령까지 진행하다 2400초 타임아웃에
걸렸다 — 후자는 `FLAG_CANDIDATE` 를 한 번도 내지 않았다. 워커 컨테이너의 `mem_limit` 이 4 GiB 인데, 프로덕션 rev/crypto
job 은 `worker_mem.py` 의 확장 사다리(3단계, 최대 13.5 GiB)를 받는다 — 프로브에는
그 사다리가 없다. 즉 **R2 의 ultra 실패는 effort 가 아니라 프로브 환경의 제약**이다.
low 는 같은 문제에서 angr 를 돌려보고 155~803초에 스스로 포기했으므로 OOM 에
도달할 일이 없었다. R2 는 solve rate 비교로 쓸 수 없다.

## 4. 운영상 결론

**1) 품질 차이는 실재하고, R1 기준으로 0/3 대 3/3 이다.** 도구를 쓰는 실전
rev 문제에서 low 는 한 번도 풀지 못했고 ultra 는 매번 풀었다.

**2) 더 중요한 것은 실패의 모양이다.** low 6런 중 **4런이 틀린 플래그를 확신
있게 제출**했다 (날조 플래그 4개, 값 생략).
ultra 는 **스스로 결론에 도달한 3런 중 날조 0건**
이다(나머지 2런은 OOM·타임아웃으로 끊겨 결론에 닿지 못했으므로 분모에서 뺀다).
즉 low 의 실패는 "못 푼다" 가 아니라 **"틀린 답을 내놓는다"** 이다.

여기서 멈춰야 한다. **이 프로브는 그 날조가 프로덕션에서 오퍼레이터까지
도달하는지는 관측하지 못한다** — judge·reviewer·하베스터가 바로 그런 후보를
걸러내려고 있는 컴포넌트인데 프로브에는 없다. 실제로 `DH{000…0}` 은
`_is_placeholder_flag` 의 해시 폭 휴리스틱이 잡으라고 만든 모양이다. 측정된
사실은 "solo 모델이 low 에서 6런 중 4런 날조" 까지이고, 파이프라인 통과율은
별도 측정이 필요하다.

**3) 비용은 약 6~7배다.** R1 기준 출력 토큰 6.9배, wall clock 6.0배, 입력 토큰
7.4배. 입력의 95% 이상은 캐시 히트라 실제 과금 비중은 출력·추론 토큰 쪽이다.

**4) 그래서 `gpt_effort` 를 낮출 이유는 없다.** 6~7배 비용을 아끼는 대신
정답률이 3/3 에서 0/3 으로 떨어지고 오답 보고가 생긴다. 현재 설정(`ultra`)이
맞다. 단, `ultra` 는 API 가 공개 목록에 싣지 않은 값이므로 모델 교체 시
`ultra2` 처럼 400 으로 거부될 가능성이 있다 — `max` 가 문서화된 대체값이다.

## 5. 이 측정이 답하지 않는 것

* 파이프라인 전체의 solve rate. 프로브는 solo `codex exec` 라
  judge/reviewer/monitor/harvester 와 메모리 사다리가 없다.
* `ultra` 대 `max` 의 차이. R1 은 xhigh/max/ultra 를 구분하지 못했고(전부 정답)
  실전 배터리에는 max arm 을 넣지 않았다.
* 프롬프트가 `Do not stop until you have either printed a FLAG_CANDIDATE line
  or exhausted your ideas` 로 무언가 내놓도록 압박한다. 양쪽 arm 이 동일 프롬프트라
  비교는 성립하지만, 날조율의 절대값은 프로덕션 프롬프트보다 부풀려졌을 수 있다.
* n=3 이다. R1 의 0/3 대 3/3 은 분리가 완전해서 신호가 분명하지만,
  효과 크기를 수치로 주장할 표본은 아니다.

### 프로덕션과의 차이 (해석 시 감안할 것)

프로덕션은 `model_context_window=1050000`,
`model_auto_compact_token_limit=240000` 을 함께 넘기는데 이 프로브는 넘기지
않는다. 두 arm 이 같은 조건이므로 비교 자체는 공정하지만, 긴 rev 세션에서
자동 압축이 더 일찍 걸려 **양쪽 모두 프로덕션보다 불리하게** 측정된다.
또 프로브는 solo `codex exec` 라 judge/reviewer/monitor/harvester 와 메모리
사다리가 없다 — 파이프라인 전체의 solve rate 가 아니라 모델 effort 변수만
분리한 값이다.
