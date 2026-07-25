/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,   // 0.0.0.0 바인딩 — WSL2/원격에서 Windows 브라우저로 접속 가능하게(localhost-only 미노출 방지)
    port: 5174,   // EDR 콘솔(5173)과 겹치지 않게
  },
  test: {
    // ProcessImpact 순수 로직 테스트는 DOM 불필요 → node 환경(가볍고 빠름).
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
