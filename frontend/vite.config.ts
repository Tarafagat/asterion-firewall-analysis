import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Este plugin sirve su propio build (ver internal/httpapi — el mismo
// patrón que backend-core usa para frontend-core), así que en producción
// no hace falta ningún proxy: JS y API viven en el mismo puerto. En dev,
// PLUGIN_PORT apunta al proceso Go corriendo suelto (ver README).
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    proxy: {
      "/api": `http://127.0.0.1:${process.env.PLUGIN_PORT || 8081}`,
    },
  },
});
