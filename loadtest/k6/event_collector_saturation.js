// 감사 U-3 「부하 포화점」 — 램프 스트레스 테스트
// =================================================
// nightly k6(event_collector_ingest.js)는 *고정* 200 EPS에서 임계 통과 여부만 본다.
// 그건 "이 부하는 견디는가?"만 답할 뿐, "어디서 무너지는가?"(=포화점)는 알려주지 않는다.
// 이 스크립트는 event_collector /events 에 EPS를 단계적으로 올리며(각 단계 독립 측정)
// SLO(p95<500ms AND 실패<1%)를 마지막으로 지킨 EPS(=saturation_eps)와 처음 깨진 EPS
// (=first_break_eps)를 자동 산출한다. 결과는 loadtest/results/ 에 커밋되어 회귀 추적된다.
//
// 인증: nightly 워크플로와 동일하게 SERVICE_TOKEN 미설정 + RBAC_ALLOW_INSECURE_DEV=true
// 이면 토큰 없이 dev-mode ingest 가 통과한다(event_collector_ingest.js 와 동일 전제).
import http from 'k6/http';

// 각 단계의 목표 EPS. 100 → 2400 까지 비선형 증가로 무릎(knee)을 촘촘히 훑는다.
const RATES = [100, 200, 400, 700, 1000, 1400, 1800, 2400];
const STAGE_SEC = 25;   // 단계별 지속(정상상태 도달에 충분하되 CI 예산 내)
const GAP_SEC = 3;      // 단계 간 여유(큐 배수·측정 분리)
const SLO_P95_MS = 500; // 포화 판정 지연 상한
const SLO_ERR = 0.01;   // 포화 판정 실패율 상한(1%)

const scenarios = {};
const thresholds = {};
let start = 0;
for (const r of RATES) {
  scenarios[`r${r}`] = {
    executor: 'constant-arrival-rate',
    rate: r,
    timeUnit: '1s',
    duration: `${STAGE_SEC}s`,
    preAllocatedVUs: Math.min(1500, Math.max(50, Math.ceil(r * 0.6))),
    maxVUs: Math.min(3000, r * 3),
    startTime: `${start}s`,
    tags: { rate: `${r}` },   // 이 단계의 모든 메트릭에 rate 태그 부여
    exec: 'ingest',
  };
  // 태그별 서브메트릭을 만들기 위해 임계를 정의(abortOnFail 없음 — 전 곡선을 다 본다).
  thresholds[`http_req_duration{rate:${r}}`] = [`p(95)<${SLO_P95_MS}`];
  thresholds[`http_req_failed{rate:${r}}`] = [`rate<${SLO_ERR}`];
  start += STAGE_SEC + GAP_SEC;
}

export const options = { scenarios, thresholds };

export function ingest() {
  http.post('http://localhost:8010/events', JSON.stringify({
    event_id: `${__VU}-${__ITER}-${Date.now()}`,
    event_type: 'red_attack_started', actor: 'red', target_asset: 'ground_station',
    vuln_id: 'GS-001', phase: 'initial_access', team_id: `team_${__VU % 16}`,
  }), { headers: { 'Content-Type': 'application/json' } });
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
    const dur = data.metrics[`http_req_duration{rate:${r}}`];
    const fail = data.metrics[`http_req_failed{rate:${r}}`];
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
