import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,   // 0.0.0.0 바인딩 — WSL2/Tailscale/원격에서 접속 가능하게
    port: 5176,   // EDR 5173 / LiveFire 5174 / SIEM 5175 와 겹치지 않게
  },
});
