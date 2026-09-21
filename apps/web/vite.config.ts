import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const apiTarget = `http://127.0.0.1:${process.env['API_PORT'] ?? '3000'}`;
const proxy = {
  '/auth': apiTarget,
  '/vault': apiTarget,
  '/health': apiTarget,
};

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true, proxy },
  preview: { port: 4173, strictPort: true, proxy },
  build: { target: 'es2022', sourcemap: false },
  worker: { format: 'es' },
});
