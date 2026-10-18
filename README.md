# guardrails

A Claude Code mod that checks every Bash and PowerShell command before it runs, and refuses three kinds:

- **Secret files.** Anything that names `.env`, `.env.local`, `.env.*.local`, a `*.pem` file, a private SSH key (`id_rsa`, `id_ed25519`, …) or a path under `~/.ssh`. `.env.example`, `Test-Path .env`, `ls`, `uv run --env-file .env` and `echo .env >> .gitignore` still work.
- **`data/raw` is read-only.** Deleting, moving, renaming, in-place editing (`sed -i`), redirecting output into it, copying into it, or `find … -delete` there. Reading from it and copying out of it still work.
- **Recursive deletes of protected folders:**
  - drive roots and Windows system folders
  - your home folder, every folder directly in it, and every folder directly in a OneDrive folder
  - your projects folder (optional) and every whole project in it
  - any `.git` folder
  - `.`, `..` and `*`

  It also refuses `pwsh -EncodedCommand`, which it cannot read.

It looks inside `pwsh -Command`, `powershell -c`, `bash -c`, `cmd /c`, `eval` and `Invoke-Expression`. When it refuses a command, Claude is told why and to ask you to run it yourself.

It pairs with permission deny rules such as `Read(//**/.env)` and `Edit(//**/data/raw/**)` in `~/.claude/settings.json`. Those rules cover Claude's file tools; this mod covers the shell.

## Install

Needs Claude Code 2.1.287 or later with function hooks on (`CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`).

At the prompt of a terminal session:

```
/plugin install guardrails --marketplace daldaman/claude-guardrails
```

From a shell:

```
claude plugin install guardrails --marketplace daldaman/claude-guardrails
```

In the desktop app, click + next to the prompt box, then Plugins. Choose Add marketplace with `daldaman/claude-guardrails`, then Add plugin.

## Setting

**Projects folder** (`projectsFolder`) is a folder that holds your projects, one per subfolder, such as `~/code`. Once it's set, neither that folder nor any whole project in it can be deleted recursively. It's empty by default. Set it in `/config`.

## Limits

- It can't tell where a relative path points, because a hook doesn't see the shell's current directory. `rm -rf myproject`, typed from inside your projects folder, gets through.
- It doesn't see paths that arrive on a pipe, as in `Get-ChildItem … | Remove-Item`.
- It doesn't see what a script does inside its own code.
- It allows downloads into `data/raw` (`curl -o`) on purpose.
- If the mod itself errors, the command runs. That way a bug in it can never block every shell call.

## Develop

```
claude plugin validate .
claude plugin test .
```
