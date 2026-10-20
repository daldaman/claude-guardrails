import type { EngineInterface, Register } from 'claude-code'

// Shell-side companion to the permission deny rules in ~/.claude/settings.json.
// Those rules stop Claude's file tools from reading secrets or editing data/raw, and
// stop git force-push/reset/clean; they cannot see what a Bash or PowerShell command
// does with those paths. This guard reads each command (and any pwsh -Command,
// bash -c, cmd /c, eval or Invoke-Expression payload inside it) and refuses three
// things: touching a secret file, changing data/raw, and a recursive delete of a
// protected folder. It fails open: a hook that throws is skipped, so a bug here can
// never brick every shell call the way a fail-closed guard would.

export type Shell = 'bash' | 'pwsh' | 'cmd'
type Segment = { words: string[]; redirects: string[] }

const END = `(?=$|[\\s'"\`;|&)>,:])`
const SECRET = [
  new RegExp(`(^|[\\s'"=/:(,])\\.env(\\.local|\\.[a-z0-9_-]+\\.local)?${END}`), // .env, .env.local, .env.*.local; not .env.example
  new RegExp(`\\.pem${END}`),
  new RegExp(`(^|[\\s'"/=])id_(rsa|ed25519|ecdsa|dsa)${END}`), // private keys; id_*.pub stays readable
  /\/\.ssh(\/|$|[\s'"])/,
]
// Commands that name a secret path without printing its contents.
const SECRET_EXEMPT = new Set(['test-path', 'test', '[', '[[', 'ls', 'dir', 'gci', 'get-childitem', 'ssh', 'scp', 'sftp', 'ssh-add', 'ssh-agent', 'ssh-keygen'])
const GIT_EXEMPT = new Set(['check-ignore', 'ls-files', 'status', 'rm'])
const IGNORE_WRITERS = new Set(['echo', 'printf', 'add-content', 'ac', 'write-output', 'out-file', 'set-content', 'tee'])

const RAW = /(^|[/=])data\/raw(\/|$)/
const MODIFY = new Set([
  'rm', 'rmdir', 'unlink', 'shred', 'truncate', 'touch', 'chmod', 'chown', 'ln', 'tee', 'mv', 'move', 'rename', 'ren', 'dd',
  'remove-item', 'ri', 'del', 'erase', 'rd', 'clear-content', 'clc', 'set-content', 'sc', 'add-content', 'ac', 'out-file',
  'new-item', 'ni', 'rename-item', 'rni', 'move-item', 'mi', 'tee-object', 'attrib', 'icacls',
])
const COPY = new Set(['cp', 'copy', 'copy-item', 'cpi', 'xcopy', 'robocopy', 'rsync', 'install'])
const DELETE = new Set(['rm', 'rmdir', 'rd', 'remove-item', 'ri', 'del', 'erase', 'unlink', 'shred'])
const PREFIXES = /^(sudo|command|exec|nohup|time|builtin|xargs)$/

/** Splits a command into simple commands at ; | & newlines, parentheses and braces, keeping quoted text whole. */
export function segments(command: string, shell: Shell): Segment[] {
  const out: Segment[] = []
  let seg: Segment = { words: [], redirects: [] }
  let cur = ''
  let has = false
  let quote = ''
  let redirect = false
  const word = () => {
    if (has) (redirect ? seg.redirects : seg.words).push(cur)
    if (has) redirect = false
    cur = ''
    has = false
  }
  const cut = () => {
    word()
    redirect = false
    if (seg.words.length || seg.redirects.length) out.push(seg)
    seg = { words: [], redirects: [] }
  }
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!
    if (quote) {
      if (c === quote) quote = ''
      else cur += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      has = true
      continue
    }
    if (c === '`') {
      if (shell === 'bash') cut() // command substitution
      else if (shell === 'pwsh') { cur += command[++i] ?? ''; has = true } // escape character
      else { cur += c; has = true }
      continue
    }
    if (c === '{' && cur.endsWith('$')) { // ${HOME}, ${env:USERPROFILE}
      const close = command.indexOf('}', i)
      const end = close < 0 ? command.length : close + 1
      cur += command.slice(i, end)
      i = end - 1
      continue
    }
    if (c === ' ' || c === '\t' || c === '\r' || c === '<') {
      word()
      continue
    }
    if (c === '>') {
      if (/^[0-9*&]?$/.test(cur)) { cur = ''; has = false } else word() // 2> names a stream, not a word
      if (command[i + 1] === '>') i++
      if (command[i + 1] === '&') { i += 2; continue } // 2>&1 redirects to a stream, not a file
      redirect = true
      continue
    }
    if (';|&\n(){}'.includes(c)) {
      cut()
      continue
    }
    cur += c
    has = true
  }
  cut()
  return out
}

/** A path as one comparable form: lower case, forward slashes, /c/... for drives, home expanded, trailing /* and / dropped. */
export function norm(word: string, home: string): string {
  let p = word.replace(/\\/g, '/').toLowerCase().trim()
  if (home) p = p.replace(/^(~|\$home|\$\{home\}|\$env:userprofile|\$\{env:userprofile\}|%userprofile%)(?=\/|$)/, home)
  p = p.replace(/^\/mnt\/([a-z])(?=\/|$)/, '/$1').replace(/^([a-z]):(?=\/|$)/, '/$1').replace(/\/{2,}/g, '/')
  if (p === '/*' || p === '/**') return '/'
  while (p.length > 1 && /.\/(\*\*?|\.)?$/.test(p)) p = p.replace(/\/(\*\*?|\.)?$/, '')
  return p
}

/** Where paths are judged from: the home folder and the optional projects folder, both already normalized. */
export type Ctx = { home: string; projects: string }

// `root` itself, or a folder directly inside it.
function isAtOrJustUnder(p: string, root: string): boolean {
  return p === root || (p.startsWith(`${root}/`) && !p.slice(root.length + 1).includes('/'))
}

/**
 * Folders no recursive delete may name: drive roots and system folders; home, every
 * folder directly in it, and every folder directly in a OneDrive folder (where
 * Windows moves Desktop and Documents); the projects folder and each project in it;
 * any .git; and the current or a parent directory.
 */
export function isProtected(p: string, { home, projects }: Ctx): boolean {
  if (['', '/', '.', '*', '~', '.git'].includes(p) || /^(\.\.\/)*\.\.$/.test(p)) return true
  if (/^\/[a-z]$/.test(p) || /(^|\/)\.git$/.test(p)) return true
  if (/^\/[a-z]\/(users|windows|program files|program files \(x86\)|programdata)$/.test(p) || /^\/[a-z]\/windows\//.test(p)) return true
  if (home && isAtOrJustUnder(p, home)) return true
  if (home && p.startsWith(`${home}/onedrive`) && /^[^/]+\/[^/]+$/.test(p.slice(home.length + 1))) return true
  return projects !== '' && isAtOrJustUnder(p, projects)
}

function verbOf(word: string): string {
  return (word.replace(/\\/g, '/').split('/').pop() ?? '').toLowerCase().replace(/\.exe$/, '')
}

function isFlag(arg: string, shell: Shell): boolean {
  return arg.startsWith('-') || (shell === 'cmd' && /^\/[a-z]$/i.test(arg)) // cmd switches are /s, /q; its paths are C:\...
}

function isRecursive(verb: string, lower: string[], shell: Shell): boolean {
  if (shell === 'cmd') return ['rd', 'rmdir', 'del', 'erase'].includes(verb) && lower.includes('/s')
  return lower.some(a =>
    a === '--recursive' ||
    (/^-[a-z]+$/.test(a) && a.includes('r') && (shell === 'bash' || /^-[rf]+$/.test(a))) || // rm -rf, -Rf, -r
    (shell === 'pwsh' && a.length >= 2 && '-recurse'.startsWith(a)), // Remove-Item -Recurse, -Rec, -r
  )
}

function checkSegment(seg: Segment, shell: Shell, ctx: Ctx, depth: number): string | undefined {
  const { home } = ctx
  const words = seg.words.slice()
  while (words.length && (PREFIXES.test(words[0]!.toLowerCase()) || /^[a-z_][a-z0-9_]*=/i.test(words[0]!))) {
    const dropped = words.shift()!.toLowerCase()
    if (dropped === 'xargs') while (words.length && words[0]!.startsWith('-')) words.shift()
  }
  const verb = verbOf(words[0] ?? '')
  const args = words.slice(1)
  const lower = args.map(a => a.toLowerCase())

  // Wrappers: check the command they run.
  if (depth < 4) {
    if (verb === 'pwsh' || verb === 'powershell') {
      const flags = lower.map(a => a.replace(/^\//, '-'))
      if (flags.some(a => a === '-ec' || (a.length >= 2 && '-encodedcommand'.startsWith(a))))
        return 'runs an encoded PowerShell command, which this guard cannot read'
      const at = flags.findIndex(a => (a.length >= 2 && '-command'.startsWith(a)) || a === '-cwa' || a.startsWith('-commandwithargs'))
      if (at >= 0) return check(args.slice(at + 1).join(' '), 'pwsh', ctx, depth + 1)
    }
    if (['bash', 'sh', 'zsh', 'dash', 'ksh'].includes(verb)) {
      const at = lower.findIndex(a => /^-[a-z]*c$/.test(a))
      if (at >= 0) return check(args.slice(at + 1).join(' '), 'bash', ctx, depth + 1)
    }
    if (verb === 'cmd') {
      const at = lower.findIndex(a => a === '/c' || a === '/k')
      if (at >= 0) return check(args.slice(at + 1).join(' '), 'cmd', ctx, depth + 1)
    }
    if (verb === 'eval' || verb === 'invoke-expression' || verb === 'iex') return check(args.join(' '), shell, ctx, depth + 1)
  }

  // 1. Secret files.
  const text = [...words, ...seg.redirects].join(' ').replace(/\\/g, '/').toLowerCase()
  const exempt =
    SECRET_EXEMPT.has(verb) ||
    (verb === 'git' && GIT_EXEMPT.has(lower[0] ?? '')) ||
    (IGNORE_WRITERS.has(verb) && text.includes('.gitignore'))
  if (!exempt && SECRET.some(r => r.test(text.replace(/--env-file(=|\s+)\S+/g, ' '))))
    return 'touches a secret file (.env, .env.local, *.pem, an SSH key or ~/.ssh)'

  // 2. data/raw is read-only.
  const isRaw = (w: string) => RAW.test(norm(w, home))
  const skipValue = new Set(['-include', '-exclude', '-filter'])
  const targets = args.filter((a, i) => !isFlag(a, shell) && !skipValue.has(lower[i - 1] ?? ''))
  if (seg.redirects.some(isRaw)) return 'writes into data/raw, which is read-only'
  if (MODIFY.has(verb) && targets.some(isRaw)) return 'changes or deletes files in data/raw, which is read-only'
  if ((verb === 'sed' || verb === 'perl') && lower.some(a => /^-[a-z]*i/.test(a)) && targets.some(isRaw))
    return 'edits files in data/raw in place, which is read-only'
  if (COPY.has(verb)) {
    const named = lower.findIndex(a => a.length >= 3 && '-destination'.startsWith(a))
    const dest = named >= 0 ? args[named + 1] : verb === 'robocopy' || verb === 'copy-item' || verb === 'cpi' ? targets[1] : targets[targets.length - 1]
    if (dest !== undefined && isRaw(dest)) return 'copies into data/raw, which is read-only'
  }
  if (verb === 'find' && (lower.includes('-delete') || (lower.includes('-exec') && lower.some(a => a === 'rm' || a === 'remove-item')))) {
    const base = targets[0] ?? '.'
    if (isRaw(base)) return 'deletes files in data/raw, which is read-only'
    if (isProtected(norm(base, home), ctx)) return `deletes files across a protected folder (${norm(base, home)})`
  }

  // 3. Recursive deletes of protected folders.
  if (DELETE.has(verb) && isRecursive(verb, lower, shell)) {
    const hit = targets.map(t => norm(t, home)).find(p => isProtected(p, ctx))
    if (hit !== undefined) return `recursively deletes a protected folder (${hit || '/'})`
  }
  return undefined
}

/** Why the command is refused, or undefined when it may run. */
export function check(command: string, shell: Shell, ctx: Ctx, depth = 0): string | undefined {
  for (const seg of segments(command, shell)) {
    const why = checkSegment(seg, shell, ctx, depth)
    if (why) return why
  }
  return undefined
}

let home: Promise<string> | undefined

async function homeDir($: EngineInterface): Promise<string> {
  const raw = (await $.env.get('USERPROFILE')) || (await $.env.get('HOME')) || ''
  return raw ? norm(raw, '') : ''
}

/** Forgets the cached home folder, for tests. */
export function resetHome() {
  home = undefined
}

function refusal(name: string, why: string): string {
  return `${name}: blocked, because this command ${why}. If it is really needed, ask the user to run it themselves.`
}

async function context($: EngineInterface, projectsFolder: string): Promise<Ctx> {
  home ??= homeDir($).catch(() => '')
  const h = await home
  return { home: h, projects: projectsFolder ? norm(projectsFolder, h) : '' }
}

export const register: Register = (on, options) => {
  const projectsFolder = String((options as Record<string, unknown> | undefined)?.projectsFolder ?? '').trim()

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const why = check(e.command, 'bash', await context($, projectsFolder))
    return why ? { deny: refusal($.plugin.name, why) } : next(e)
  })

  on('tool.call', { tool: 'PowerShell' }, async ($, e, next) => {
    const why = check(e.command, 'pwsh', await context($, projectsFolder))
    return why ? { deny: refusal($.plugin.name, why) } : next(e)
  })
}
