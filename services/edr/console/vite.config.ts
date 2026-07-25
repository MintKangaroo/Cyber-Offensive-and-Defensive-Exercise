import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,   // 0.0.0.0 바인딩 — WSL2/원격에서 Windows 브라우저로 접속 가능하게
    port: 5173,
  },
});
