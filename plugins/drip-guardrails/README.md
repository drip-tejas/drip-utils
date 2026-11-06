# drip-guardrails

Safety rails for every tool call Claude Code makes, in every permission mode.
One `PreToolUse` hook that decides **allow / ask / deny** before anything runs,
and writes an audit line for every ask and deny.

The policy in one breath:

| Rule | What it means |
|---|---|
| **No merges** | No `gh pr merge`, no merge via API or MCP, no PR approvals, no auto-merge. |
| **No protected-branch pushes** | `main`, `master`, `prod*`, `release*`, `stable`, `live`, `trunk` are push-only via pull request. No force pushes anywhere (`--force-with-lease` on your own branch asks). |
| **No production writes** | Cloud CLIs, databases, HTTP, SSH: reads are free, writes ask, writes that name a production target are denied. |
| **All deletes reversible** | `rm` is replaced by `drip-trash` (moves, prints the restore command). Cloud deletes, `DROP`/`TRUNCATE`/`DELETE`, `git clean`, stash drops, branch force-deletes, MCP delete tools: denied. Trash and archive actions ask. |
| **Secrets: no read, no copy** | `.env*`, keys, cloud credential stores, tfstate, `env` dumps, `kubectl get secret`, `gh auth token` and the rest: denied. Any secret-shaped token (`AKIA…`, `ghp_…`, `sk-ant-…`, private key blocks, DB URLs with passwords) in anything the agent is about to write, run or send: denied. |
| **Outward and money ask** | Email send, publishing, sharing, comments, package publish, ad spend, paid generation, scheduled tasks. |
| **No self-escalation** | The guard will not edit its own files, uninstall itself, launch Claude without permissions, or silently edit `settings.json` / `.mcp.json` / shell rc files. |

Build artefacts (`node_modules`, `dist`, caches, `/tmp`) may still be `rm`'d so
normal work is not slowed down. Everything else goes through the trash.

## Install

```bash
claude plugin marketplace add drip-tejas/drip-utils
claude plugin install drip-guardrails@drip-utils
```

Restart Claude Code. Needs `python3` (stdlib only).

To make the rails apply to **every** session on a machine, including ones
started by scripts, install at user scope (the default) rather than per project.
For a managed fleet, put the same hook in managed settings; see the note on
layers below.

## What this is, and is not

This is a guardrail against mistakes: the wrong branch, the wrong database, the
`rm -rf` that looked safe, the `.env` that ended up in a commit. It runs in the
agent's own process and reads shell commands with regexes, so a determined
adversary can route around it (obfuscated commands, a script written then run,
a compiled binary). The plugin closes the common paths (`bash -c`, `eval`,
`xargs`, `find -exec`, subshells, `python -c`, pipe-to-shell) and asks on
anything it cannot see into, but it is layer one, not the only layer.

**Layer two is server-side, and you should set it up as well:**

| Rule | Real enforcement |
|---|---|
| No merges / protected branches | GitHub branch protection: require PR, require review from a human, no force pushes, no deletions. Give the agent's token or GitHub App no merge rights. |
| No production writes | A read-only IAM role, project or profile for the agent's credentials. A read replica or read-only DB user. Separate credentials for staging. |
| Reversible deletes | Soft-delete columns, bucket versioning, deletion protection on databases, `terraform prevent_destroy`, trash policies on Drive and mail. |
| Secrets | Do not put secrets in the sandbox at all. In Claude Code on the web, `request_credential` injects them at the proxy so the agent never sees the value. Locally, use `op run`, `doppler run`, or `direnv` with files the guard already blocks from being read. |
| Spend | Platform-side budget caps on ad accounts and credit pools. |

## Configuration

All optional, all environment variables read by the hook (set them where Claude
Code starts, or in the `env` block of `settings.json`).

| Variable | Default | Effect |
|---|---|---|
| `DRIP_GUARD_ENABLED` | `true` | `false` turns the guard off |
| `DRIP_GUARD_MODE` | `enforce` | `strict` turns every ask into a deny (for headless runs); `audit` logs decisions but never blocks |
| `DRIP_GUARD_FAIL` | `ask` | what happens if the guard itself errors: `ask`, `deny` or `allow` |
| `DRIP_GUARD_PROTECTED_BRANCHES` | `main,master,prod,production,release,release/*,stable,live,trunk` | glob list |
| `DRIP_GUARD_PROD_PATTERNS` | `prod,prd,production,live` | words that mark a target as production (matched as whole words, case-insensitive) |
| `DRIP_GUARD_RM_ALLOW` | unset | colon-separated path prefixes where plain `rm` is allowed |
| `DRIP_GUARD_RM_STRICT` | `false` | `true` denies `rm` everywhere, build artefacts included |
| `DRIP_GUARD_MCP_WRITES` | `ask` | `allow` or `deny` for generic MCP write tools (deletes, secrets, merges and outward actions keep their own rules) |
| `DRIP_GUARD_MCP_ALLOW_SERVERS` | `Claude_Docs` | MCP servers whose writes are allowed without asking |
| `DRIP_GUARD_HTTP_WRITES` | `ask` | `allow` or `deny` for POST/PUT/PATCH to non-local hosts |
| `DRIP_GUARD_ALLOW_SUDO` | `false` | permit `sudo` |
| `DRIP_GUARD_SECRET_SCAN` | `true` | scan tool inputs for secret-shaped tokens |
| `DRIP_GUARD_EXTRA_SECRET_GLOBS` | unset | extra basename or path globs to treat as secret files |
| `DRIP_GUARD_MAX_BUDGET_MINOR` | unset | deny ad budgets or bids above this amount (in the platform's minor unit) |
| `DRIP_GUARD_TRASH` | `~/.drip-trash` | where `drip-trash` moves things |
| `DRIP_GUARD_AUDIT` | `~/.drip-guard/audit.jsonl` | audit log path |
| `DRIP_GUARD_AUDIT_ALL` | `false` | also log allowed calls |

## The trash

```
drip-trash PATH...          move into the trash, print the restore command
drip-trash --list           batches and their contents
drip-trash --restore BATCH  put a batch back (skips anything that now exists)
drip-trash --empty BATCH    real delete; refuses unless a human types the name at a terminal
```

When the guard denies an `rm` it tells the model the full path to `drip-trash`,
so no PATH setup is needed. Paths are stored absolute under each batch, so
nothing collides and restore is a plain move.

## Audit log

One JSON line per ask or deny:

```json
{"ts":"2026-11-06T17:02:11Z","session":"s_…","mode":"acceptEdits","cwd":"/work/app","tool":"Bash","decision":"deny","rule":"protected-branch","reason":"Pushing to main is off. Push a feature branch and open a pull request.","input":"git push origin main"}
```

Secret-shaped tokens are redacted before they reach the log.

## How decisions are made

* Every tool input is scanned for secret-shaped strings first.
* `Bash` commands are split into segments (quote-aware, including `$(…)`,
  `bash -c`, `eval`, `xargs`, `find -exec`, `ssh host cmd`) and each segment is
  classified by program: `git`, `gh`, cloud CLIs (verb table: destroy, write,
  read, plus a production check on flags, env vars and the active
  `kubectl`/`gcloud` context), database clients (SQL scanned for DDL/DML),
  HTTP clients (method and host), docker, package registries, system tools.
* `Read`/`Glob`/`Grep`/`Write`/`Edit` check the path against the secret-file
  rules and the self-protection list.
* MCP tools are classified by name (`delete_*`, `send_*`, `create_*`, `get_*`)
  with a table of overrides for GitHub, mail, calendar, drive, sheets, ads and
  session-management tools.
* The worst decision wins. `allow` prints nothing, so your normal permission
  prompts still apply on top.
* Any internal error in the guard becomes an `ask`, never a silent pass.

## Tests

```bash
python3 test/test_guard.py
```

Over 600 table-driven cases: commands that must stay allowed, and for each rule
the commands that must be caught, including the evasions.

## License

MIT.
