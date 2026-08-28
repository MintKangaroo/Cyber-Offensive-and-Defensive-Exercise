// 감사 U-3 「부하 포화점」 — 램프 스트레스 테스트
// =================================================
// nightly k6(event_collector_ingest.js)는 *고정* 200 EPS에서 임계 통과 여부만 본다.
// 그건 "이 부하는 견디는가?"만 답할 뿐, "어디서 무너지는가?"(=포화점)는 알려주지 않는다.
// 이 스크립트는 event_collector /events 에 EPS를 플래토 단위로 올리며(각 플래토 독립 측정)
// SLO(p95<500ms AND 실패<1%)를 마지막으로 지킨 EPS(=saturation_eps)와 처음 깨진 EPS
// (=first_break_eps)를 자동 산출한다. 결과는 loadtest/results/ 에 커밋되어 회귀 추적된다.
//
// 설계 주의(중요): VU 풀은 **단일 ramping-arrival-rate 시나리오 하나**만 쓴다. 초기 버전은
// 플래토마다 별도 시나리오를 둬 preAllocatedVUs가 시작 시 전부 초기화(합 수천 VU)되면서
// k6 프로세스 자체가 러너 CPU를 잠식 → 지연이 서버가 아닌 k6-side thrash를 반영했다.
// 단일 풀(50~600)을 램프 내내 재사용하면 그 왜곡이 사라진다.
//
// 인증: nightly 워크플로와 동일하게 SERVICE_TOKEN 미설정 + RBAC_ALLOW_INSECURE_DEV=true
// 이면 토큰 없이 dev-mode ingest 가 통과한다(event_collector_ingest.js 와 동일 전제).
import http from 'k6/http';
import exec from 'k6/execution';

// 저-rate 그리드: 초기 측정으로 event_collector의 실 포화점이 ~40 EPS 부근임이 드러났다
// (nightly의 "200 EPS" ingest는 실제로 ~38 req/s만 달성·80% dropped·p95 2.3s — 200을 이미
//  한참 넘어섬). 원인은 요청마다 동기 SQLite commit(fsync)을 async 루프에서 직렬 수행하는 것.
// 따라서 knee를 정밀 측정하려면 수십 EPS 대역을 촘촘히 훑어야 한다.
const RATES = [10, 20, 30, 40, 50, 75, 100, 150];
const SCEN_SEC = 60;      // rate별 시나리오 지속(정상상태 확보)
const MEASURE_TAIL = 40;  // 마지막 40초(정상상태)만 측정 — 시작 20s(연결·VU 예열) 제외
const GAP_SEC = 10;       // rate 시나리오 사이 배수(drain)
const WARMUP_RATE = 10;   // 콜드스타트 흡수
const WARMUP_SEC = 15;
const SLO_P95_MS = 500;
const SLO_ERR = 0.01;

// 핵심 방법론: 연속 램프(단일 시나리오)는 서버가 초반에 포화되면 백로그가 이후 전 구간을
// 오염시켜 per-rate 귀속이 무의미해진다(그래서 200 EPS가 1000보다 나쁘게 나왔다). 대신
// **rate마다 독립 constant-arrival-rate 시나리오**를 두고 사이에 GAP_SEC 배수를 넣어 서버를
// 비운 뒤 다음 rate를 측정한다. 각 시나리오의 정상상태 tail만 재 SLO를 판정한다.
// VU 풀은 낮게 잡아(시작 시 전 시나리오 preAllocatedVUs 합이 초기화됨) k6-side thrash를 막는다.
function clamp(x, lo, hi) { return Math.max(lo, Math.min(hi, x)); }

const scenarios = {
  warmup: {
    executor: 'constant-arrival-rate', rate: WARMUP_RATE, timeUnit: '1s',
    duration: `${WARMUP_SEC}s`, preAllocatedVUs: 20, maxVUs: 60, startTime: '0s',
    exec: 'ingest', tags: { rate: 'warmup' },
  },
};
const MEASURE_WINDOWS = [];
let cursor = WARMUP_SEC + GAP_SEC;        // 예열 후 배수
for (const r of RATES) {
  scenarios[`r${r}`] = {
    executor: 'constant-arrival-rate', rate: r, timeUnit: '1s',
    duration: `${SCEN_SEC}s`,
    // knee 근처 지연이 수초까지 오르므로 rate를 채우려면 VU가 rate×지연만큼 필요하다.
    preAllocatedVUs: clamp(Math.ceil(r * 1.5), 10, 250),
    maxVUs: clamp(Math.ceil(r * 6), 40, 600),
    startTime: `${cursor}s`,
    exec: 'ingest',
    tags: { rate: `${r}` },
  };
  // 측정창 = 이 시나리오의 마지막 MEASURE_TAIL초(정상상태)
  MEASURE_WINDOWS.push({ rate: r, start: cursor + (SCEN_SEC - MEASURE_TAIL), end: cursor + SCEN_SEC });
  cursor += SCEN_SEC + GAP_SEC;
}

const thresholds = {};
for (const r of RATES) {
  // rate 태그(전 구간) 대신 정상상태 창만 SLO 판정하도록 별도 서브메트릭 rate_ss 를 쓴다.
  thresholds[`http_req_duration{rate_ss:${r}}`] = [`p(95)<${SLO_P95_MS}`];
  thresholds[`http_req_failed{rate_ss:${r}}`] = [`rate<${SLO_ERR}`];
}

export const options = {
  discardResponseBodies: true,          // k6 메모리·CPU 절약
  scenarios,
  thresholds,
};

// 정상상태 창 안에서 발생한 요청에만 rate_ss 태그를 추가로 붙인다(SLO 판정 대상).
// 시나리오 tags.rate 는 전 구간에 붙지만, rate_ss 는 tail 창에서만 붙는다.
function steadyStateTag() {
  const t = exec.instance.currentTestRunDuration / 1000;
  for (const w of MEASURE_WINDOWS) {
    if (t >= w.start && t < w.end) return `${w.rate}`;
  }
  return '';
}

export function ingest() {
  // rate_ss: 정상상태 창 안이면 rate, 아니면 빈 문자열(SLO 판정 대상에서 제외).
  const ss = steadyStateTag();
  const tags = ss ? { rate_ss: ss } : {};
  http.post('http://localhost:8010/events', JSON.stringify({
    event_id: `${__VU}-${__ITER}-${Date.now()}`,
    event_type: 'red_attack_started', actor: 'red', target_asset: 'ground_station',
    vuln_id: 'GS-001', phase: 'initial_access', team_id: `team_${__VU % 16}`,
  }), { headers: { 'Content-Type': 'application/json' }, tags });
}

function round(x, d = 1) {
  if (x === null || x === undefined || Number.isNaN(x)) return null;
  const m = Math.pow(10, d);
  return Math.round(x * m) / m;
}

export function handleSummary(data) {
  const rows = [];
  let saturation = 0;        // SLO를 마지막으로 지킨 EPS(포화 직전 수용 한계)
  let firstBreak = null;     // SLO가 처음 깨진 EPS
  for (const r of RATES) {
    const dur = data.metrics[`http_req_duration{rate_ss:${r}}`];
    const fail = data.metrics[`http_req_failed{rate_ss:${r}}`];
    const p95 = dur && dur.values ? dur.values['p(95)'] : null;
    const errRate = fail && fail.values ? fail.values.rate : null;
    const durOk = dur && dur.thresholds ? Object.values(dur.thresholds).every((t) => t.ok) : false;
    const failOk = fail && fail.thresholds ? Object.values(fail.thresholds).every((t) => t.ok) : false;
    const ok = durOk && failOk;
    rows.push({ rate: r, p95_ms: round(p95), err_rate: round(errRate, 4), slo_ok: ok });
    if (ok) saturation = r;
    else if (firstBreak === null) firstBreak = r;
  }

  const result = {
    test: 'event_collector_saturation',
    target: 'POST /events (event_collector, 단일 인스턴스·SQLite WAL)',
    slo: `p95<${SLO_P95_MS}ms AND error_rate<${SLO_ERR * 100}%`,
    saturation_eps: saturation,       // 이 EPS까지 SLO 유지(수용 한계)
    first_break_eps: firstBreak,      // 이 EPS에서 처음 SLO 붕괴(=포화점)
    stages: rows,
    generated_at: new Date().toISOString(),
  };

  const lines = [
    '',
    '=== event_collector 부하 포화점 (U-3) ===',
    `SLO: ${result.slo}`,
    'EPS      p95(ms)   err%     SLO',
    ...rows.map((x) => {
      const eps = String(x.rate).padEnd(8);
      const p95 = (x.p95_ms === null ? '-' : String(x.p95_ms)).padEnd(9);
      const err = (x.err_rate === null ? '-' : (x.err_rate * 100).toFixed(2)).padEnd(8);
      return `${eps} ${p95} ${err} ${x.slo_ok ? 'OK' : 'BREAK'}`;
    }),
    `수용 한계(saturation): ${saturation} EPS`,
    `포화점(first break):   ${firstBreak === null ? '측정 범위 내 없음(전 단계 통과)' : firstBreak + ' EPS'}`,
    '',
  ];

  const json = JSON.stringify(result, null, 2);
  const stamp = __ENV.STAMP || 'latest';
  const out = { stdout: lines.join('\n') };
  out[`loadtest/results/event_collector_saturation.${stamp}.json`] = json;
  out['loadtest/results/event_collector_saturation.latest.json'] = json;
  return out;
}
