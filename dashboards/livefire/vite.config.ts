/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,   // EDR 콘솔(5173)과 겹치지 않게
  },
  test: {
    // ProcessImpact 순수 로직 테스트는 DOM 불필요 → node 환경(가볍고 빠름).
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
