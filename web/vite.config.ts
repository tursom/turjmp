import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8080',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    chunkSizeWarningLimit: 1024,
    rolldownOptions: {
      onLog(level, log, defaultHandler) {
        if (
          log.code === 'INVALID_ANNOTATION' &&
          log.id?.includes('node_modules/@vueuse/core/')
        ) {
          return
        }

        defaultHandler(level, log)
      },
      output: {
        codeSplitting: {
          groups: [
            {
              name: 'vendor-vue',
              test: /node_modules[\\/](vue|vue-router|pinia)[\\/]/,
              priority: 30,
            },
            {
              name: 'vendor-element-plus',
              test: /node_modules[\\/](element-plus|@element-plus)[\\/]/,
              priority: 20,
            },
            {
              name: 'vendor-terminal',
              test: /node_modules[\\/](@xterm|xterm)[\\/]/,
              priority: 20,
            },
            {
              name: 'vendor',
              test: /node_modules[\\/]/,
              priority: 10,
            },
          ],
        },
      },
    },
  },
})
