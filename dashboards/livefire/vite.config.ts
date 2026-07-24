import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,   // EDR 콘솔(5173)과 겹치지 않게
  },
});
