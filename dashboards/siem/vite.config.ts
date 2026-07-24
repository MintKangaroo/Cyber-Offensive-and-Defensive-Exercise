import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5175,   // EDR(5173), Live Fire(5174)와 겹치지 않게
  },
});
