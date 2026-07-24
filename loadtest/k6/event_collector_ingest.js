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
    http_req_duration: ['p(99)<200'],
  },
};

export default function () {
  http.post('http://localhost:8010/events', JSON.stringify({
    event_id: `${__VU}-${__ITER}-${Date.now()}`,
    event_type: 'red_attack_started', actor: 'red', target_asset: 'ground_station',
    vuln_id: 'GS-001', phase: 'initial_access', team_id: `team_${__VU % 16}`,
  }), { headers: { 'Content-Type': 'application/json' } });
}
