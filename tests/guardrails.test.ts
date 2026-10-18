import { describe, expect, test } from 'claude-code/testing'

import { check, norm, resetHome, type Ctx, type Shell } from '../hooks/register'

const CTX: Ctx = { home: '/c/users/me', projects: '/c/users/me/code' }

const BLOCKED: [Shell, string][] = [
  ['bash', 'cat .env'],
  ['bash', 'ls && cat app/.env'],
  ['pwsh', 'Get-Content C:\\Users\\me\\code\\app\\.env'],
  ['pwsh', 'type .env.local'],
  ['bash', `python -c "print(open('.env').read())"`],
  ['bash', 'cat ~/.ssh/id_ed25519'],
  ['bash', 'cat ~/.ssh/id_ed25519.pub'], // all of ~/.ssh is off limits
  ['pwsh', 'Get-Content $env:USERPROFILE\\.ssh\\config'],
  ['bash', 'openssl x509 -in cert.pem -text'],
  ['bash', 'bash -lc "cat .env"'],
  ['bash', 'rm -rf data/raw/2020'],
  ['bash', 'echo x > data/raw/notes.txt'],
  ['bash', 'mv data/raw/a.csv data/clean/'],
  ['pwsh', 'Copy-Item x.csv -Destination data\\raw\\x.csv'],
  ['bash', 'sed -i s/a/b/ data/raw/f.txt'],
  ['bash', 'find data/raw -name "*.tmp" -delete'],
  ['pwsh', 'Remove-Item data\\raw\\old.csv'],
  ['pwsh', 'Remove-Item -Recurse -Force C:\\Users\\me'],
  ['pwsh', 'rm -r -fo $HOME\\Downloads'],
  ['bash', 'rm -rf ~/OneDrive/Documents'],
  ['bash', 'rm -rf ~'],
  ['bash', 'rm -rf ~/'],
  ['bash', 'rm -rf C:/'],
  ['bash', 'rm -fr /c/Users/me/code/app'],
  ['bash', 'rm -rf ~/code'],
  ['bash', 'rm -rf .git'],
  ['bash', 'rm -rf ./*'],
  ['bash', 'pwsh -NoProfile -Command "Remove-Item -Recurse -Force $HOME"'],
  ['pwsh', 'cmd /c rd /s /q C:\\'],
  ['bash', 'pwsh -EncodedCommand ZQBjAGgAbwA='],
]

const ALLOWED: [Shell, string][] = [
  ['bash', 'cat .env.example'],
  ['bash', 'ls -a'],
  ['bash', 'git status'],
  ['bash', 'echo .env >> .gitignore'],
  ['pwsh', 'Test-Path .env'],
  ['bash', 'uv run --env-file .env python x.py'],
  ['bash', 'cat deploy/id_ed25519.pub'],
  ['bash', 'cp data/raw/a.csv data/clean/a.csv'],
  ['bash', 'Rscript code/R/01_clean.R data/raw/x.csv'],
  ['bash', 'mkdir -p data/raw'],
  ['bash', 'rm -rf build node_modules'],
  ['bash', 'rm -rf /c/Users/me/code/app/output/tmp'],
  ['bash', 'rm -rf ~/Downloads/old-installer'],
  ['pwsh', 'Remove-Item -Recurse -Force .\\dist'],
  ['pwsh', 'Remove-Item -Force C:\\Users\\me\\Downloads\\x.zip'],
  ['bash', 'git log --oneline 2>&1 | head'],
  ['pwsh', 'echo $env:USERPROFILE'],
  ['pwsh', 'Get-ChildItem ~/.ssh'],
]

describe('guardrails', () => {
  test('blocks secret reads, data/raw changes and protected recursive deletes', () => {
    for (const [shell, command] of BLOCKED) expect([command, check(command, shell, CTX) !== undefined]).toEqual([command, true])
  })

  test('lets everyday commands through', () => {
    for (const [shell, command] of ALLOWED) expect([command, check(command, shell, CTX)]).toEqual([command, undefined])
  })

  test('protects a whole project only when a projects folder is set', () => {
    const noProjects = { ...CTX, projects: '' }
    expect(check('rm -rf /c/Users/me/code/app', 'bash', noProjects)).toBeUndefined()
    expect(check('rm -rf /c/Users/me/code/app', 'bash', CTX)).toContain('protected folder')
  })

  test('normalizes Windows, Git Bash and home forms to one path', () => {
    expect(norm('C:\\Users\\me\\', '')).toBe(CTX.home)
    expect(norm('/c/Users/me/*', '')).toBe(CTX.home)
    expect(norm('$env:USERPROFILE\\OneDrive', CTX.home)).toBe(`${CTX.home}/onedrive`)
    expect(norm('~', CTX.home)).toBe(CTX.home)
  })

  test('denies a blocked Bash call before it runs and passes a safe one', { options: { projectsFolder: '~/code' } }, async ($, on) => {
    resetHome()
    const ran: string[] = []
    on('env.get', (_$: any, e: any) => ({ value: e.name === 'USERPROFILE' ? 'C:\\Users\\me' : undefined }))
    on('tool.call', (_$: any, e: any) => {
      ran.push(e.command)
      return { result: {}, text: 'ok' }
    })
    const blocked: any = await $.tool.call({ tool: 'Bash', command: 'rm -rf ~/code/app' } as any)
    const passed: any = await $.tool.call({ tool: 'Bash', command: 'git status' } as any)
    expect(ran).toEqual(['git status'])
    expect(blocked.isError ?? blocked.deny !== undefined).toBe(true)
    expect(String(blocked.text ?? blocked.deny)).toContain('protected folder')
    expect(passed.text).toBe('ok')
  })
})
