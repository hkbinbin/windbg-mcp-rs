# skills/

WorkBuddy / agent **skills** for this project, versioned alongside the code.

## windbg-cli

`windbg-cli/SKILL.md` teaches an agent how to debug a Windows target with this
project's two binaries (`windbg_mcp_headless.exe` + `windbg_cli.exe`): opening a
session (launch / attach / kernel), the full `windbg_cli do <action>` surface
(breakpoints, stepping, registers, memory, disassembly, backtrace, dump, raw
commands), daemon management, and the project-specific gotchas (blocked
commands, symbol fixups, alias display).

### Install (user-level)

Copy the skill into your WorkBuddy skills directory:

```bash
# Windows (Git Bash)
cp -r skills/windbg-cli ~/.workbuddy/skills/windbg-cli
```

Or project-level, so teammates share it:

```bash
mkdir -p .workbuddy/skills
cp -r skills/windbg-cli .workbuddy/skills/windbg-cli
```

The skill is also shipped in each GitHub release as
`windbg-cli-skill-<tag>.zip`, so users who only download the binaries can grab
it too.
