import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  scenarios: {
    concurrent_teams: {
      executor: 'per-vu-iterations',
      vus: 16,
      iterations: 50,
      maxDuration: '5m',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<500'],
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const teamId = `team_${__VU}`;
  const res = http.get(`http://localhost:8001/api/telemetry?sensor_id=SOL-PANEL-1`, {
    headers: { 'X-Team-Id': teamId },
  });
  check(res, { 'status 200': (r) => r.status === 200 });
  sleep(Math.random() * 2);
}
