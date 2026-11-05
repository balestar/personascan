import { spawn } from 'node:child_process'

const children = []

function run(command, args) {
  const child = spawn(command, args, {
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env: process.env,
  })
  children.push(child)
  child.on('exit', (code) => {
    for (const other of children) {
      if (other !== child) other.kill('SIGTERM')
    }
    process.exit(code ?? 0)
  })
}

run('node', ['scripts/local-api.mjs'])
run('npx', ['vite'])

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    for (const child of children) child.kill(signal)
    process.exit(0)
  })
}
