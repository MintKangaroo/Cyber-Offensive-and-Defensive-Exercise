// WEB-020 배포용 서비스 — KEPCO 스마트미터 설정 병합 API (프로토타입 오염).
// 설정 병합이 __proto__ 키를 걸러내지 않고 재귀 병합해 Object.prototype 을 오염시킬 수 있다.
// isAdmin 을 프로토타입에 심으면 이후 생성되는 빈 객체({})도 isAdmin=true 가 되어 관리자
// 전용 /api/admin/flag 가 열린다. PATCH_WEB_020=true 면 위험 키를 건너뛰어 차단한다.
const express = require('express');
const crypto = require('crypto');

const SECRET = process.env.CHALLENGE_SECRET;
if (!SECRET) { console.error('CHALLENGE_SECRET 미설정 — fail-fast'); process.exit(1); }
const PATCHED = (process.env.PATCH_WEB_020 || 'false').toLowerCase() === 'true';

function staticFlag() {
  const sig = crypto.createHash('sha256').update(`WEB-020:${SECRET}`).digest('hex').slice(0, 16);
  return `flag{proto_pollution_${sig}}`;
}

const app = express();
app.use(express.json());
const CONFIG = {}; // 미터 설정 저장소

function merge(dst, src) {
  for (const k in src) {
    if (PATCHED && (k === '__proto__' || k === 'constructor' || k === 'prototype')) continue; // 방어
    if (src[k] && typeof src[k] === 'object' && !Array.isArray(src[k])) {
      if (typeof dst[k] !== 'object' || dst[k] === null) dst[k] = {};
      merge(dst[k], src[k]);
    } else {
      dst[k] = src[k];
    }
  }
  return dst;
}

app.get('/health', (_req, res) => res.json({ status: 'ok', patched: PATCHED, service: 'kepco-meter-config' }));
app.get('/api/version', (_req, res) => res.json({ protocol: 'ad-http-v1', service: 'kepco-meter-config' }));

app.post('/api/config/merge', (req, res) => {
  merge(CONFIG, req.body || {});          // 취약: 재귀 병합(__proto__ 미필터)
  res.json({ merged: true, keys: Object.keys(CONFIG) });
});

app.get('/api/admin/flag', (_req, res) => {
  const user = {};                         // 권한 없는 빈 사용자 객체
  if (user.isAdmin === true) {             // 프로토타입 오염 시 true
    return res.json({ grid_master_token: staticFlag() });
  }
  return res.status(403).json({ error: '관리자 권한 필요' });
});

const PORT = parseInt(process.env.PORT || '8120', 10);
app.listen(PORT, '0.0.0.0', () => console.log(`[web020] KEPCO meter config on :${PORT}`));
