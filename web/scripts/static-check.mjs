import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const root = resolve(import.meta.dirname, '..')

function read(path) {
  return readFileSync(resolve(root, path), 'utf8')
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message)
  }
}

const indexHTML = read('index.html')
const loginView = read('src/views/login/LoginView.vue')
const appLayout = read('src/components/layout/AppLayout.vue')
const dashboardView = read('src/views/dashboard/DashboardView.vue')
const handlers = read('../internal/api/handler/handlers.go')

assert(!indexHTML.includes('<title>web</title>'), 'index.html must not use the Vite default title')
assert(indexHTML.includes('<title>Turjmp</title>'), 'index.html must use the Turjmp default title')
assert(!loginView.includes('/vite.svg'), 'login page must not use the Vite logo')
assert(!appLayout.includes('/vite.svg'), 'app layout must not use the Vite logo')
assert(
  handlers.includes('{Key: "connection_tokens"') &&
    handlers.includes('Object: "/api/v1/authentication/connection-tokens/"'),
  'backend access map must expose the connection_tokens capability',
)
assert(
  dashboardView.includes('canIssueConnectionTokens') &&
    dashboardView.includes("authStore.canAccess('connection_tokens')") &&
    /<el-card\s+v-if="canIssueConnectionTokens"[\s\S]*Generate Connection Token/.test(dashboardView),
  'dashboard connection token card must be gated by connection_tokens access',
)

console.log('static checks passed')
