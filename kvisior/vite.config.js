import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  css: {
    preprocessorOptions: {
      scss: {
        silenceDeprecations: ['import'],
      },
    },
  },
  plugins: [react()],
  server: {
    proxy: {
      '/v1/': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/auth/': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/api/': {
        target: 'http://tracee-bridge.wolfee-watcher.svc.cluster.local:8081',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/api/, ''),
      },
      '/sensor/': {
        target: 'http://sensor.wolfee-watcher.svc.cluster.local:8080',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/sensor/, ''),
      },
      '/sentry/': {
        target: 'http://sentry-audit.wolfee-watcher.svc.cluster.local:8080',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/sentry/, ''),
      },
      '/anomaly/': {
        target: 'http://anomaly-detector.wolfee-watcher.svc.cluster.local:8080',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/anomaly/, ''),
      },
      '/audit/': {
        target: 'http://audit-runner.wolfee-watcher.svc.cluster.local:8080',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/audit/, ''),
      },
      '/scanner/': {
        target: 'http://scanner-agent.wolfee-watcher.svc.cluster.local:9090',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/scanner/, ''),
      },
      '/honey/': {
        target: 'http://honey-operator.wolfee-watcher.svc.cluster.local:9095',
        changeOrigin: true,
        rewrite: path => path.replace(/^\/honey/, ''),
      },
    }
  }
})
