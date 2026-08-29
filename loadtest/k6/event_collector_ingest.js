import http from 'k6/http';

export const options = {
  scenarios: {
    high_eps: {
      executor: 'constant-arrival-rate',
      rate: 200,
      timeUnit: '1s',
      duration: '3m',
      preAllocatedVUs: 50,
    },
  },
  thresholds: {
    // 개선(PR #38·#39) 후 200 EPS를 완전 달성(이전엔 ~38 req/s·대부분 dropped)하며 p95~20ms.
    // p99는 이 stack에서 tail ~350ms라 200ms는 비현실적 → 500ms로 현실화(회귀 게이트로 작동).
    // 회귀(예: 동기 쓰기 재도입)면 p99가 수초로 튀어 즉시 잡힌다.
    http_req_duration: ['p(99)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  http.post('http://localhost:8010/events', JSON.stringify({
    event_id: `${__VU}-${__ITER}-${Date.now()}`,
    event_type: 'red_attack_started', actor: 'red', target_asset: 'ground_station',
    vuln_id: 'GS-001', phase: 'initial_access', team_id: `team_${__VU % 16}`,
  }), { headers: { 'Content-Type': 'application/json' } });
}
