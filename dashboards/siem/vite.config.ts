import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: process.env.VITE_BASE || "/",   // 프로덕션 gateway 서브경로(/ops, /red 등)
  plugins: [react()],
  server: {
    host: true,   // 0.0.0.0 바인딩 — WSL2/원격에서 Windows 브라우저로 접속 가능하게
    port: 5175,   // EDR(5173), Live Fire(5174)와 겹치지 않게
  },
});
