import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
declare const process: { env: Record<string, string | undefined> };

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: Number(process.env.PORT) || 5173,
    hmr: false,
    allowedHosts: true,
  },
  preview: {
    host: "0.0.0.0",
    port: Number(process.env.PORT) || 4173,
    // @ts-ignore - preview allowedHosts exists in Vite 4.4+
    allowedHosts: true,
  },
});
