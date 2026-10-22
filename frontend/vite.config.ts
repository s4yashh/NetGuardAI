import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// During development, requests to /api are forwarded to the FastAPI backend.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Recharts makes the single bundle ~620 kB; fine for a locally served dashboard.
  build: { chunkSizeWarningLimit: 800 },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
    },
  },
});
