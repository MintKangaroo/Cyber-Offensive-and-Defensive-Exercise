import http from "k6/http";
import { check, sleep } from "k6";

// Full profile: 12 teams, 2 services, 100 short rounds. Match/team bootstrap is
// performed before k6; no exploit is executed here.
export const options = {
  scenarios: {
    scoreboard_readers: {
      executor: "constant-vus",
      vus: Number(__ENV.SCOREBOARD_VUS || 24),
      duration: __ENV.DURATION || "5m",
    },
    flag_submitters: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.SUBMISSIONS_PER_SECOND || 20),
      timeUnit: "1s",
      duration: __ENV.DURATION || "5m",
      preAllocatedVUs: 12,
      maxVUs: 48,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.02"],
    http_req_duration: ["p(95)<750"],
  },
};

const base = __ENV.AD_API || "http://localhost:8100";
const match = __ENV.MATCH_ID || "ad-load";
const tokens = (__ENV.COMPETITOR_TOKENS || "").split(",").filter(Boolean);
const safeInvalidFlag = "FLAG{loadprofileinvalidtoken000000000}";

export default function () {
  if (__ITER % 3 === 0 || tokens.length === 0) {
    const response = http.get(`${base}/api/attack-defense/matches/${match}/scoreboard`);
    check(response, { "scoreboard responds": (r) => r.status === 200 });
  } else {
    const token = tokens[__VU % tokens.length];
    const response = http.post(
      `${base}/api/attack-defense/matches/${match}/flags/submit`,
      JSON.stringify({ flag: safeInvalidFlag }),
      { headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` } },
    );
    check(response, { "bounded submit response": (r) => [200, 429].includes(r.status) });
  }
  sleep(0.05);
}
