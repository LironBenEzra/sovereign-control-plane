import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development the UI runs on its own port and proxies API calls to the control
// plane. In the Docker image the built files are served by the control plane itself,
// so the browser only ever talks to one origin.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/v1": "http://localhost:8000",
      "/healthz": "http://localhost:8000",
    },
  },
});
