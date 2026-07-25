import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: process.env.VITE_BASE || "/",   // 프로덕션 gateway 서브경로(/ops, /red 등)
  plugins: [react()],
  server: {
    host: true,   // WSL2/Tailscale/원격 접속 대응
    port: 5177,   // EDR 5173 / LiveFire 5174 / SIEM 5175 / RedPortal 5176 와 겹치지 않게
  },
});
