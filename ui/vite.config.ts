import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => ({
  build: {
    outDir: mode === 'cloud' ? 'dist-cloud' : 'dist',
    chunkSizeWarningLimit: 650,
  },
  define: { 'import.meta.env.VITE_DEPLOY_TARGET': JSON.stringify(mode === 'cloud' ? 'cloud' : 'local') },
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8765',
        changeOrigin: true,
      },
    },
  },
}));
