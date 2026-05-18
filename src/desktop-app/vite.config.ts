import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// Tauri expects a fixed dev port and leaves the console output to the CLI.
export default defineConfig({
  plugins: [solid()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
});
