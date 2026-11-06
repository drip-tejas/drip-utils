#!/usr/bin/env python3
"""drip-guardrails: a PreToolUse policy for Claude Code. Stdlib only.

Reads the hook payload on stdin, decides allow / ask / deny, and prints the
decision as hook JSON. "allow" prints nothing, so the normal permission flow
still runs. Any internal error becomes an "ask" (configurable), never a silent
pass: the harness treats a crashed hook as fail-open, so we never crash.

Policy, in one breath:
  * no PR merges, approvals, or pushes to protected branches
  * no production writes; reads are fine
  * no irreversible deletes anywhere (files, branches, cloud, databases, MCP)
  * secrets are neither read nor copied
  * outward actions (send, publish, spend, schedule) and self-modification ask

This is a guardrail against mistakes, not a sandbox against an adversary. The
real enforcement for each rule lives server-side (branch protection, read-only
IAM, secrets kept out of the sandbox). See README.md.
"""
import fnmatch
import json
import os
import posixpath
import re
import shlex
import subprocess
import sys
import time

ALLOW, ASK, DENY = "allow", "ask", "deny"
RANK = {ALLOW: 0, ASK: 1, DENY: 2}


class Decision:
    __slots__ = ("decision", "rule", "reason")

    def __init__(self, decision, rule, reason):
        self.decision = decision
        self.rule = rule
        self.reason = reason

    def __repr__(self):
        return "Decision(%s, %s, %r)" % (self.decision, self.rule, self.reason)


def allow():
    return Decision(ALLOW, "", "")


def worst(decisions):
    best = None
    for d in decisions:
        if d is None:
            continue
        if best is None or RANK[d.decision] > RANK[best.decision]:
            best = d
    return best or allow()


# --------------------------------------------------------------------------
# Configuration (all from environment variables; see README)
# --------------------------------------------------------------------------

def _truthy(v, default):
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _csv(v, default):
    if v is None or v.strip() == "":
        return list(default)
    return [x.strip() for x in v.split(",") if x.strip()]


class Config:
    def __init__(self, env=None):
        env = os.environ if env is None else env
        g = env.get
        self.enabled = _truthy(g("DRIP_GUARD_ENABLED"), True)
        self.mode = (g("DRIP_GUARD_MODE") or "enforce").strip().lower()  # enforce|strict|audit
        self.fail = (g("DRIP_GUARD_FAIL") or ASK).strip().lower()  # ask|deny|allow
        self.protected_branches = _csv(
            g("DRIP_GUARD_PROTECTED_BRANCHES"),
            ["main", "master", "prod", "production", "release", "release/*", "stable", "live", "trunk"],
        )
        prod = _csv(g("DRIP_GUARD_PROD_PATTERNS"), ["prod", "prd", "production", "live"])
        self.prod_re = re.compile(
            r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z0-9])" % "|".join(prod), re.IGNORECASE
        )
        self.rm_allow = [x for x in (g("DRIP_GUARD_RM_ALLOW") or "").split(":") if x]
        self.rm_strict = _truthy(g("DRIP_GUARD_RM_STRICT"), False)
        self.mcp_writes = (g("DRIP_GUARD_MCP_WRITES") or ASK).strip().lower()
        self.mcp_allow_servers = set(_csv(g("DRIP_GUARD_MCP_ALLOW_SERVERS"), ["Claude_Docs"]))
        self.http_writes = (g("DRIP_GUARD_HTTP_WRITES") or ASK).strip().lower()
        self.allow_sudo = _truthy(g("DRIP_GUARD_ALLOW_SUDO"), False)
        self.secret_scan = _truthy(g("DRIP_GUARD_SECRET_SCAN"), True)
        self.extra_secret_globs = _csv(g("DRIP_GUARD_EXTRA_SECRET_GLOBS"), [])
        self.trash_dir = g("DRIP_GUARD_TRASH") or "~/.drip-trash"
        self.audit_path = g("DRIP_GUARD_AUDIT") or "~/.drip-guard/audit.jsonl"
        self.audit_all = _truthy(g("DRIP_GUARD_AUDIT_ALL"), False)
        cap = (g("DRIP_GUARD_MAX_BUDGET_MINOR") or "").strip()
        self.max_budget = int(cap) if cap.isdigit() else None
        self.home = g("HOME") or os.path.expanduser("~")
        self.plugin_root = g("CLAUDE_PLUGIN_ROOT") or ""

    def is_prod(self, text):
        return bool(text) and bool(self.prod_re.search(text))

    def is_protected_branch(self, name):
        if not name:
            return False
        name = name.strip()
        for p in ("refs/heads/", "refs/remotes/origin/", "origin/"):
            if name.startswith(p):
                name = name[len(p):]
        return any(fnmatch.fnmatchcase(name, pat) for pat in self.protected_branches)


class Runner:
    """Runs small read-only shell probes. Tests replace it."""

    def run(self, args, cwd=None):
        try:
            out = subprocess.run(
                args, cwd=cwd or None, capture_output=True, text=True, timeout=3
            )
            if out.returncode != 0:
                return None
            return out.stdout
        except Exception:
            return None


class Context:
    def __init__(self, cwd, cfg, runner=None, session_id="", permission_mode=""):
        self.cwd = cwd or os.getcwd()
        self.cfg = cfg
        self.runner = runner or Runner()
        self.session_id = session_id
        self.permission_mode = permission_mode


# --------------------------------------------------------------------------
# Secrets: paths, env var names, and secret-shaped tokens
# --------------------------------------------------------------------------

SECRET_ENV_NAME_RE = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|CLIENT_SECRET|DSN|"
    r"DATABASE_URL|CONNECTION_STRING|COOKIE|SESSION_ID|AUTH\b|APIKEY)",
    re.IGNORECASE,
)

SECRET_BASENAME_DENY = [
    r"^\.env$", r"^\.env\..+$", r"^.+\.env$", r"^\.envrc$",
    r"^.+\.(pem|key|p12|pfx|jks|keystore|ppk|p8|keytab|gpg|kdbx|ovpn)$",
    r"^id_(rsa|dsa|ecdsa|ed25519)(_[\w.-]+)?$",
    r"^.+\.secrets?$", r"^secrets?\..+$",
    r"^.*secrets?\.(ya?ml|json|toml|env|txt|ini|cfg|properties)$",
    r"^client_secret.*\.json$", r"^credentials?(\..+)?\.json$", r"^.*credentials.*\.json$",
    r"^service[-_]?account.*\.json$", r"^.*adminsdk.*\.json$",
    r"^.*\.tfstate(\.backup)?$",
    r"^\.?_?netrc$", r"^\.npmrc$", r"^\.pypirc$", r"^\.pgpass$", r"^\.my\.cnf$",
    r"^\.git-credentials$", r"^\.boto$", r"^\.s3cfg$", r"^\.vault-token$",
    r"^\.terraformrc$", r"^terraform\.rc$", r"^\.sentryclirc$", r"^\.htpasswd$",
    r"^master\.key$", r"^\.credentials\.json$", r"^\.claude\.json$",
    r"^AuthKey_.*\.p8$", r"^credentials\.db$", r"^access_tokens\.db$",
    r"^application_default_credentials\.json$", r"^hosts\.yml$",
]
SECRET_BASENAME_EXEMPT = [
    r"^\.env\.(example|sample|template|dist|defaults|schema|d\.ts)$",
    r"^.+\.pub$", r"^known_hosts$",
]
SECRET_BASENAME_ASK = [
    r"^.+\.tfvars$", r"^wp-config\.php$", r"^local\.settings\.json$", r"^\.yarnrc\.yml$",
    r"^\.(bash|zsh|python|mysql|psql|node_repl)_history$",
]
# Directories whose contents are secret stores. Keys are relative to $HOME
# unless absolute. Values: regex of basenames that are NOT secret inside.
SECRET_DIRS = {
    ".ssh": r"^(.+\.pub|known_hosts(\.old)?|config|authorized_keys|environment|rc)$",
    ".aws": r"^(config|cli)$",
    ".config/gcloud": r"^(configurations|config_sentinel|active_config|logs|properties|\.last.*|virtenv|gce)$",
    ".azure": r"^(config|clouds\.config|az\.json|az\.sess|commands|logs|telemetry.*)$",
    ".kube": r"^(cache|http-cache)$",
    ".docker": r"^(cli-plugins|contexts|buildx|run|daemon\.json|features\.json)$",
    ".gnupg": r"^(gpg\.conf|gpg-agent\.conf|dirmngr\.conf|pubring\.kbx|trustdb\.gpg|openpgp-revocs\.d)$",
    ".password-store": r"^\.gpg-id$",
    ".config/op": r"^$",
    ".config/doppler": r"^$",
    ".config/gh": r"^(config\.yml)$",
    ".vercel": r"^$",
    ".wrangler": r"^$",
    ".railway": r"^$",
    ".fly": r"^$",
    ".heroku": r"^$",
    ".netlify": r"^$",
    ".supabase": r"^$",
    ".local/share/keyrings": r"^$",
    "Library/Keychains": r"^$",
    "/etc/shadow": r"^$",
    "/etc/gshadow": r"^$",
    "/etc/sudoers": r"^$",
    "/etc/sudoers.d": r"^$",
    "/etc/ssl/private": r"^$",
}

_SECRET_DENY_RE = [re.compile(p, re.IGNORECASE) for p in SECRET_BASENAME_DENY]
_SECRET_EXEMPT_RE = [re.compile(p, re.IGNORECASE) for p in SECRET_BASENAME_EXEMPT]
_SECRET_ASK_RE = [re.compile(p, re.IGNORECASE) for p in SECRET_BASENAME_ASK]

# Token shapes. (regex, decision, label)
SECRET_TOKEN_PATTERNS = [
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", DENY, "private key material"),
    (r"\bAKIA[0-9A-Z]{16}\b", DENY, "AWS access key id"),
    (r"\bASIA[0-9A-Z]{16}\b", DENY, "AWS temporary access key id"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", DENY, "GitHub token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{60,}\b", DENY, "GitHub fine-grained token"),
    (r"\bsk-ant-[A-Za-z0-9_-]{20,}", DENY, "Anthropic API key"),
    (r"\bsk-(?:proj-|live-|svcacct-)?[A-Za-z0-9_-]{32,}\b", DENY, "API key (sk- prefix)"),
    (r"\b(?:sk|rk|pk)_live_[A-Za-z0-9]{16,}\b", DENY, "Stripe live key"),
    (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", DENY, "Slack token"),
    (r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", DENY, "Slack webhook"),
    (r"\bAIza[0-9A-Za-z_-]{35}\b", DENY, "Google API key"),
    (r"\bya29\.[0-9A-Za-z_-]{20,}", DENY, "Google OAuth access token"),
    (r"\bglpat-[A-Za-z0-9_-]{20,}\b", DENY, "GitLab token"),
    (r"\bnpm_[A-Za-z0-9]{36}\b", DENY, "npm token"),
    (r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", DENY, "SendGrid key"),
    (r"\bhf_[A-Za-z0-9]{34}\b", DENY, "Hugging Face token"),
    (r"\bpypi-AgEI[A-Za-z0-9_-]{20,}", DENY, "PyPI token"),
    (r"\bdo[po]_v1_[a-f0-9]{64}\b", DENY, "DigitalOcean token"),
    (r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b", DENY, "Shopify token"),
    (r"\bEAA[A-Za-z0-9]{60,}\b", DENY, "Meta access token"),
    (r"\bSK[0-9a-f]{32}\b", DENY, "Twilio API key"),
    (r"\bAGE-SECRET-KEY-1[A-Z0-9]{50,}\b", DENY, "age secret key"),
    (r"\bsq0atp-[A-Za-z0-9_-]{22}\b", DENY, "Square token"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", ASK, "JWT"),
    (r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]{4,}@", DENY, "database URL with embedded password"),
]
_SECRET_TOKEN_RE = [(re.compile(p), d, l) for p, d, l in SECRET_TOKEN_PATTERNS]


def norm_path(p, ctx):
    """Absolute, normalised path for a token that looks like a path."""
    if not p:
        return ""
    p = p.strip().strip("'\"")
    if p.startswith("@"):
        p = p[1:]
    p = p.replace("$HOME", "~").replace("${HOME}", "~")
    if p.startswith("~"):
        p = ctx.cfg.home + p[1:]
    if not p.startswith("/"):
        p = posixpath.join(ctx.cwd, p)
    return posixpath.normpath(p)


def classify_secret_path(p, ctx):
    """Returns DENY / ASK / None for a filesystem path."""
    if not p:
        return None
    full = norm_path(p, ctx)
    base = posixpath.basename(full)
    for pat in _SECRET_EXEMPT_RE:
        if pat.match(base):
            return None
    home = ctx.cfg.home.rstrip("/")
    if re.match(r"^/proc/[^/]+/environ$", full):
        return DENY
    for d, exempt in SECRET_DIRS.items():
        root = d if d.startswith("/") else posixpath.join(home, d)
        if full == root or full.startswith(root + "/"):
            if full == root:
                return DENY
            rel = full[len(root) + 1:]
            first = rel.split("/", 1)[0]
            if re.match(exempt, first) or re.match(exempt, base):
                break
            return DENY
    for pat in _SECRET_DENY_RE:
        if pat.match(base):
            return DENY
    for g in ctx.cfg.extra_secret_globs:
        if fnmatch.fnmatch(base, g) or fnmatch.fnmatch(full, g):
            return DENY
    if base == "config" and full.endswith("/.kube/config"):
        return DENY
    for pat in _SECRET_ASK_RE:
        if pat.match(base):
            return ASK
    if full == posixpath.join(home, ".aws/config"):
        return ASK
    return None


def scan_secret_tokens(text):
    """Returns the worst (decision, label) for secret-shaped strings in text."""
    if not text:
        return None
    found = None
    for rx, dec, label in _SECRET_TOKEN_RE:
        if rx.search(text):
            if found is None or RANK[dec] > RANK[found[0]]:
                found = (dec, label)
    return found


def redact(text):
    if not text:
        return text
    for rx, _dec, _label in _SECRET_TOKEN_RE:
        text = rx.sub("[REDACTED]", text)
    return text


def iter_strings(obj, skip_keys=()):
    """All string leaves of a JSON-ish object, except under skip_keys."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k in skip_keys:
                continue
            for s in iter_strings(v, skip_keys):
                yield s
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            for s in iter_strings(v, skip_keys):
                yield s


# --------------------------------------------------------------------------
# Bash analysis helpers
# --------------------------------------------------------------------------

SUBSHELL_RE = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")
REDIRECT_RE = re.compile(r"(?<![<>&\d])\d?>{1,2}\s*([^\s;&|>]+)")

WRAPPERS = {"nice", "nohup", "time", "command", "builtin", "exec", "stdbuf", "caffeinate", "unbuffer", "script"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
INTERPRETERS = {"python", "python3", "python2", "node", "nodejs", "deno", "bun", "perl", "ruby", "php"}
READ_PROGRAMS = {
    "ls", "stat", "file", "test", "[", "[[", "find", "du", "wc", "echo", "printf", "true", "false",
    "which", "type", "basename", "dirname", "realpath", "readlink", "pwd", "cd", "tree", "md5sum", "sha256sum",
    "shasum", "python", "python3", "bash", "sh", "node", "git", "diff", "cmp", "touch", "mkdir",
}
WRITE_PROGRAMS = {"cp", "mv", "tee", "truncate", "install", "ln", "dd", "chmod", "chown", "rm", "unlink", "sed", "perl", "rsync", "scp", "tar", "zip", "gzip", "curl", "wget", "patch", "sponge"}
COPY_PROGRAMS = {"cp", "mv", "scp", "rsync", "tar", "zip", "gzip", "bzip2", "xz", "7z", "install", "ln", "dd", "tee", "curl", "wget", "base64", "xxd", "hexdump", "od", "strings", "cat", "less", "more", "head", "tail", "bat", "sed", "awk", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cut", "sort", "uniq", "tr", "jq", "yq", "openssl", "gpg", "sops", "age", "python", "python3", "node", "ruby", "perl", "php", "vim", "vi", "nano", "emacs", "code", "open", "xdg-open", "pbcopy", "xclip", "xsel", "source", ".", "export", "set", "eval", "sqlite3", "git", "nc", "ncat", "socat", "mail", "sendmail", "ssh", "sftp", "ftp"}

CLOUD_CLIS = {
    "gcloud", "gsutil", "bq", "aws", "az", "kubectl", "oc", "helm", "terraform", "tofu", "pulumi", "fly",
    "flyctl", "vercel", "heroku", "wrangler", "firebase", "supabase", "railway", "netlify", "doctl", "linode-cli",
    "hcloud", "scw", "oci", "ibmcloud", "cf", "serverless", "sls", "sam", "cdk", "eb", "kops", "eksctl",
    "gcloud.cmd", "render", "dokku", "caprover", "coolify", "argocd", "nomad", "consul", "vault", "ansible",
    "ansible-playbook", "kustomize", "skaffold", "tilt", "copilot", "amplify", "twilio", "stripe", "shopify",
    "contentful", "sanity", "sentry-cli", "datadog", "dd", "newrelic", "launchdarkly", "cloudflared", "ngrok",
}
DESTROY_VERBS = {
    "delete", "destroy", "rm", "rb", "remove", "purge", "terminate", "teardown", "drop", "flush", "prune",
    "wipe", "uninstall", "unset", "undeploy", "decommission", "obliterate", "nuke", "erase", "truncate", "down",
}
DESTROY_PREFIXES = ("delete-", "terminate-", "purge-", "deregister-", "batch-delete", "remove-", "destroy-", "flush-", "drop-", "erase-", "wipe-")
WRITE_VERBS = {
    "create", "update", "deploy", "apply", "set", "add", "patch", "put", "push", "upload", "cp", "mv", "rsync",
    "sync", "import", "export", "run", "exec", "invoke", "submit", "scale", "resize", "start", "stop", "restart",
    "reboot", "rollout", "rollback", "promote", "enable", "disable", "attach", "detach", "associate",
    "disassociate", "tag", "untag", "label", "annotate", "cordon", "uncordon", "drain", "taint", "edit",
    "replace", "expose", "autoscale", "migrate", "seed", "publish", "release", "launch", "up", "redeploy",
    "restore", "modify", "register", "grant", "revoke", "bind", "unbind", "assign", "move", "transfer", "link",
    "login", "logout", "install", "upgrade", "reset", "trigger", "cancel", "approve", "reject", "resume",
    "suspend", "pause", "clone", "copy", "snapshot", "backup", "write", "insert", "load", "mk", "publish",
    "send", "post", "ship", "env:set", "config:set", "secrets", "write", "kv:key", "d1", "r2",
}
WRITE_PREFIXES = (
    "create-", "update-", "put-", "modify-", "start-", "stop-", "reboot-", "run-", "invoke", "publish",
    "send-", "associate-", "disassociate-", "register-", "enable-", "disable-", "set-", "tag-", "untag-",
    "restore-", "import-", "copy-", "attach-", "detach-", "add-", "revoke-", "authorize-", "allocate-",
    "release-", "replace-", "reset-", "cancel-", "execute-", "batch-write", "upload-", "complete-", "admin-",
    "confirm-", "initiate-", "promote-", "reboot", "resize-", "rotate-", "schedule-", "submit-", "transfer-",
    "accept-", "activate-", "deactivate-", "apply-", "assign-", "unassign-", "approve-", "reject-", "merge-",
    "move-", "rename-", "resume-", "suspend-", "pause-", "swap-", "sync-", "test-", "validate-", "verify-",
)
# Cloud subcommands that print or mint credentials. Matched as space-joined token
# substrings on the segment's non-flag tokens.
SECRET_SUBCOMMANDS = [
    "auth print-access-token", "auth print-identity-token", "auth print-refresh-token",
    "auth application-default print-access-token", "secrets versions access", "iam service-accounts keys create",
    "auth token", "auth status --show-token", "auth status -t",
    "secretsmanager get-secret-value", "ssm get-parameter", "ssm get-parameters", "iam create-access-key",
    "configure export-credentials", "sts get-session-token", "ecr get-login-password", "ecr get-login",
    "configure get aws_secret_access_key", "configure get aws_session_token",
    "keyvault secret show", "keyvault secret download", "account get-access-token", "acr credential show",
    "ad sp credential", "storage account keys list", "webapp config appsettings list", "functionapp config appsettings list",
    "get secret", "get secrets", "describe secret", "config view --raw",
    "state pull", "output -json", "output -raw", "show -json",
    "config --show-secrets", "stack output --show-secrets",
    "config:get", "config -s", "config --shell", "config --json",
    "variables", "env pull", "functions:config:get",
    "kv get", "read", "secrets download", "secrets get", "item get", "op read",
    "find-generic-password", "find-internet-password", "dump-keychain",
    "credential fill", "token create",
    "env ls --decrypt", "env:get", "env:list",
]
SECRET_PROGRAMS = {"pass", "gopass", "bw", "lpass", "secret-tool", "keyctl"}

DB_CLIS = {
    "psql", "pgcli", "mysql", "mariadb", "mycli", "mongosh", "mongo", "redis-cli", "sqlite3", "litecli",
    "clickhouse-client", "cqlsh", "cockroach", "usql", "duckdb", "snowsql", "sqlcmd", "mssql-cli", "influx",
    "cypher-shell", "trino", "presto", "bq", "turso", "planetscale", "pscale", "neonctl",
}
DUMP_CLIS = {"pg_dump", "pg_dumpall", "mysqldump", "mariadb-dump", "mongodump", "mongoexport", "redis-dump", "sqlite3"}
SQL_DESTROY_RE = re.compile(
    r"(?i)(?<![\w.])(?:drop\s+(?:table|database|schema|index|view|collection|user|role|sequence|function|trigger|type)|"
    r"truncate(?:\s+table)?\s+\w|delete\s+from\s+\w|flushall|flushdb|"
    r"\bdel\s+\w|\bunlink\s+\w|alter\s+table\s+\w+\s+drop)|"
    r"\.(?:deleteMany|deleteOne|findOneAndDelete|dropDatabase|dropCollection|dropIndex(?:es)?|remove|drop)\s*\("
)
SQL_WRITE_RE = re.compile(
    r"(?i)(?<![\w.])(?:insert\s+into|update\s+\w+\s+set|alter\s+|create\s+(?:table|database|schema|index|view|user|role|extension)|"
    r"grant\s+|revoke\s+|replace\s+into|merge\s+into|upsert|reindex|vacuum\s+full|cluster\s+|refresh\s+materialized|"
    r"copy\s+\w+.*\s+from\s+|\\copy\s+.*\s+from\s+|load\s+data|"
    r"\bset\s+\w+\s+\S|\bmset\b|\bhset\b|\blpush\b|\brpush\b|\bsadd\b|\bzadd\b|"
    r"\bincr\b|\bdecr\b|\bexpire\b|config\s+set|script\s+flush|\brename\b|\bpersist\b)|"
    r"\.(?:insertMany|insertOne|updateOne|updateMany|replaceOne|findOneAndUpdate|findOneAndReplace|bulkWrite|createIndex|save)\s*\("
)

DESTRUCTIVE_CODE_RE = re.compile(
    r"shutil\.rmtree|os\.(?:remove|unlink|rmdir|removedirs)\s*\(|\.unlink\s*\(|rmtree\s*\(|"
    r"(?:fs|\)|fsp|promises)\.(?:promises\.)?(?:rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)\s*\(|rimraf|FileUtils\.(?:rm|rm_rf|remove)|"
    r"File\.(?:delete|unlink)|Dir\.(?:delete|rmdir)|\bunlink\s*\(|rmdir\s*\(|\bos\.system\s*\(\s*['\"]rm\b|"
    r"subprocess\.\w+\(\s*\[?\s*['\"]rm['\"]|Remove-Item|\bdel\s+/[fsq]"
)
ENV_DUMP_CODE_RE = re.compile(
    r"os\.environ(?!\s*(?:\[|\.get\(|\.setdefault\(|\.pop\(|\.update\())|process\.env(?!\s*(?:\.|\[))|"
    r"ENV\.to_h|ENV\.each|\bgetenv\(\)|\$_ENV\b|\$ENV\{|System\.getenv\(\)"
)
ENV_SECRET_CODE_RE = re.compile(
    r"(?:os\.environ(?:\[|\.get\()|process\.env(?:\.|\[)|ENV\[|getenv\(|\$ENV\{)\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)"
)
SECRET_VAR_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")

HTTP_CLIS = {"curl", "wget", "http", "https", "xh", "httpie", "curlie"}
LOCAL_HOST_RE = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|[^.]+\.local|[^.:/]+)(:\d+)?$", re.IGNORECASE)
URL_RE = re.compile(r"https?://([^/\s'\"?#]+)", re.IGNORECASE)

CONFIG_PATH_SUFFIXES = (
    "/.claude/settings.json", "/.claude/settings.local.json", "/.claude.json", "/.mcp.json",
    "/.claude/hooks", "/.claude/agents", "/.claude/commands",
)
PERSISTENCE_BASENAMES = {".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", ".zshenv", ".bash_login", ".gitconfig", "config.fish", ".tmux.conf"}


def split_segments(cmd):
    segs = []
    text = cmd or ""
    # Pull subshell bodies out as their own segments so they are analysed too.
    for _ in range(4):
        found = False
        for m in SUBSHELL_RE.finditer(text):
            inner = m.group(1) or m.group(2) or ""
            if inner.strip():
                segs.append(inner)
                found = True
        if not found:
            break
        text = SUBSHELL_RE.sub(" __subshell__ ", text)
    # Quote-aware split on ; | || && & and newlines.
    buf = []
    quote = None
    esc = False
    i = 0
    n = len(text)

    def flush():
        s = "".join(buf).strip()
        if s:
            segs.append(s)
        del buf[:]

    while i < n:
        c = text[i]
        if esc:
            buf.append(c)
            esc = False
            i += 1
            continue
        if c == "\\" and quote != "'":
            buf.append(c)
            esc = True
            i += 1
            continue
        if quote:
            if c == quote:
                quote = None
            buf.append(c)
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if c in ("\n", ";"):
            flush()
            i += 1
            continue
        if text.startswith("||", i) or text.startswith("&&", i):
            flush()
            i += 2
            continue
        if c == "|":
            flush()
            i += 1
            continue
        if c == "&" and not text.startswith("&>", i) and not (i > 0 and text[i - 1] in ">0123456789"):
            flush()
            i += 1
            continue
        buf.append(c)
        i += 1
    flush()
    return segs


def tokenize(seg):
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()


def strip_wrappers(toks):
    """Drop leading env assignments and launcher wrappers. Returns (sudo, toks)."""
    sudo = False
    i = 0
    while i < len(toks):
        t = toks[i]
        base = posixpath.basename(t)
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t):
            i += 1
        elif base in ("sudo", "doas", "pkexec"):
            sudo = True
            i += 1
            while i < len(toks) and toks[i].startswith("-"):
                i += 1
        elif base == "env":
            j = i + 1
            while j < len(toks) and (toks[j].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[j])):
                j += 1
            if j >= len(toks):
                break  # bare env: a dump, handled by caller
            i = j
        elif base in WRAPPERS:
            i += 1
            if base == "timeout" and i < len(toks):
                i += 1
            while i < len(toks) and toks[i].startswith("-") and base not in ("command", "builtin"):
                i += 1
        elif base == "timeout":
            i += 1
            while i < len(toks) and toks[i].startswith("-"):
                i += 1
            i += 1
        elif base == "xargs":
            i += 1
            while i < len(toks) and toks[i].startswith("-"):
                if toks[i] in ("-I", "-n", "-P", "-L", "-d", "-s", "-E"):
                    i += 1
                i += 1
        else:
            break
    return sudo, toks[i:]


def path_like(tok):
    if not tok or tok.startswith("-"):
        return False
    return "/" in tok or tok.startswith(".") or tok.startswith("~") or tok.startswith("@") or "." in tok


def flag_value_paths(toks):
    """Yields tokens that could be paths, including --flag=path forms and @file."""
    for t in toks:
        if t.startswith("--") and "=" in t:
            yield t.split("=", 1)[1]
        elif t.startswith("-") and len(t) > 2 and not t.startswith("--") and ("/" in t or "." in t[2:]):
            yield t[2:]
        else:
            yield t


# --------------------------------------------------------------------------
# Bash rules
# --------------------------------------------------------------------------

def check_bash(cmd, ctx, depth=0):
    cfg = ctx.cfg
    out = []
    if not cmd or not cmd.strip():
        return out
    if depth > 3:
        return out

    whole = cmd
    # Pipe-to-shell from an opaque source.
    if re.search(r"(?:curl|wget|base64\s+(?:-d|--decode|-D)|xxd\s+-r|openssl\s+enc\s+-d)[^|;\n]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|node|perl|ruby)\b", whole):
        out.append(Decision(DENY, "pipe-to-shell", "Piping downloaded or decoded content straight into an interpreter hides what runs. Save it to a file, read it, then run it."))
    if re.search(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", whole):
        out.append(Decision(DENY, "fork-bomb", "Fork bomb."))
    if re.search(r"/dev/(?:sd[a-z]|nvme\d|disk\d|hd[a-z]|mmcblk\d|xvd[a-z])", whole) and re.search(r"(?:\bdd\b|>|mkfs|wipefs|fdisk|parted|shred)", whole):
        out.append(Decision(DENY, "raw-disk", "Writing to a raw block device is not reversible."))
    if re.search(r"(?<![\w-])(?:mkfs(?:\.\w+)?|wipefs|fdisk|sfdisk|parted|diskutil\s+(?:erase|partition|reformat))\b", whole):
        out.append(Decision(DENY, "raw-disk", "Disk formatting is not reversible."))
    if re.search(r"(?<![\w/.-])(?:shutdown|reboot|halt|poweroff|init\s+[06])\b", whole) or re.search(r"systemctl\s+(?:poweroff|reboot|halt|kexec)", whole):
        out.append(Decision(DENY, "system-power", "Power or reboot commands are off limits."))
    if re.search(r"\bkill\s+(?:-\w+\s+)*-1\b|\bkillall5\b|\bpkill\s+(?:-\w+\s+)*-?(?:f\s+)?['\"]?\.\*?['\"]?\s*$", whole):
        out.append(Decision(DENY, "kill-all", "Killing every process is not reversible."))
    if re.search(r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|-R\s+777)\s+(?:/|~|\$HOME)(?:\s|$)|\bchown\s+-R\s+\S+\s+/(?:\s|$)", whole):
        out.append(Decision(DENY, "system-perms", "Recursive permission changes at the root are not reversible."))
    if re.search(r"\b(?:useradd|userdel|usermod|groupadd|groupdel|passwd|chpasswd|visudo)\b", whole):
        out.append(Decision(DENY, "system-users", "Account changes are a system-level write."))
    if re.search(r"\biptables\s+(?:-F|--flush)|\bufw\s+(?:disable|reset)|\bpfctl\s+-d\b|\bnft\s+flush\b", whole):
        out.append(Decision(DENY, "firewall", "Flushing firewall rules is not reversible from here."))
    if re.search(r"\bcrontab\s+-r\b", whole):
        out.append(Decision(DENY, "cron-wipe", "crontab -r deletes every job with no undo."))
    if re.search(r"\bcrontab\b|\bat\s+(?:now|\d)|launchctl\s+(?:load|bootstrap)|systemctl\s+(?:--user\s+)?enable\b", whole):
        out.append(Decision(ASK, "persistence", "This schedules or enables something that keeps running after the session."))
    if re.search(r"--dangerously-skip-permissions|--permission-mode[= ]bypassPermissions", whole):
        out.append(Decision(DENY, "self-escalation", "Launching Claude without permissions defeats the guard."))
    if re.search(r"\bclaude\s+plugin\s+(?:uninstall|disable|remove)\b[^\n;&|]*drip-guardrails", whole):
        out.append(Decision(DENY, "self-protect", "The guard does not uninstall itself. A human does that from the terminal."))
    elif re.search(r"\bclaude\s+(?:plugin\s+(?:uninstall|disable|remove|install)|mcp\s+(?:add|remove)|config\s+set)\b", whole):
        out.append(Decision(ASK, "self-config", "Changing Claude Code's own plugins, MCP servers or config."))
    if re.search(r"\b(?:cat|head|tail|less|more|strings|xxd)\s+/proc/(?:self|\d+|\$\$|\$\{?\w+\}?)/environ", whole) or "/proc/self/environ" in whole:
        out.append(Decision(DENY, "secret-env", "Process environments hold credentials. Not readable."))

    simulated_branch = None
    for seg in split_segments(cmd):
        toks = tokenize(seg)
        if not toks:
            continue
        sudo, toks = strip_wrappers(toks)
        if sudo and not cfg.allow_sudo:
            out.append(Decision(DENY, "sudo", "Privilege escalation is off. Set DRIP_GUARD_ALLOW_SUDO=true to permit it."))
        if not toks:
            # bare `env` / `VAR=x` with nothing else
            if re.match(r"^\s*(?:\w+=\S*\s+)*env(\s+-\w+)*\s*$", seg):
                out.append(Decision(DENY, "secret-env", "Dumping the environment exposes credentials. Read a named, non-secret variable instead."))
            continue
        prog = posixpath.basename(toks[0])
        args = toks[1:]
        nonflags = [a for a in args if not a.startswith("-")]

        # --- secrets: environment ---
        if prog in ("printenv", "env") and not nonflags:
            out.append(Decision(DENY, "secret-env", "Dumping the environment exposes credentials. Read a named, non-secret variable instead."))
        elif prog == "printenv":
            for v in nonflags:
                if SECRET_ENV_NAME_RE.search(v):
                    out.append(Decision(DENY, "secret-env", "%s looks like a credential. Not readable." % v))
        if prog in ("set", "export", "declare", "typeset") and not nonflags and (not args or args in (["-p"], ["-x"], ["-xp"])):
            out.append(Decision(DENY, "secret-env", "Listing all shell variables exposes credentials."))
        if prog in ("echo", "printf", "cat", "tee", "write") or (prog in ("python", "python3", "node") and ("-c" in args or "-e" in args)):
            for m in SECRET_VAR_REF_RE.finditer(seg):
                if SECRET_ENV_NAME_RE.search(m.group(1)):
                    out.append(Decision(DENY, "secret-env", "Printing $%s would put a credential in the transcript." % m.group(1)))
                    break

        # --- secrets: paths used by any program that copies or displays ---
        if prog not in READ_PROGRAMS or prog in ("git", "python", "python3", "node", "bash", "sh"):
            for raw in flag_value_paths(args):
                if not path_like(raw) or raw.startswith("http"):
                    continue
                cls = classify_secret_path(raw, ctx)
                if cls == DENY and prog in COPY_PROGRAMS | {"git", "source", "."} and not (prog == "git" and args[:1] not in (["add"], ["diff"], ["show"], ["log"], ["cat-file"], ["grep"], ["blame"], ["stash"])):
                    verb = "stage" if prog == "git" else "read or copy"
                    if prog in ("source", ".") or (prog in SHELLS and args and args[0] in ("-c",)):
                        break
                    out.append(Decision(DENY, "secret-file", "%s holds secrets; the guard does not %s it. Ask the user to inject it via the environment or request_credential." % (raw, verb)))
                    break
                if cls == ASK and prog in COPY_PROGRAMS | {"git"}:
                    out.append(Decision(ASK, "secret-file", "%s may contain secrets." % raw))
                    break
        if prog in ("echo", "printf", "tee", "cat", "cp", "mv", "sed", "truncate") or REDIRECT_RE.search(seg):
            for m in REDIRECT_RE.finditer(seg):
                tgt = m.group(1)
                if tgt in ("/dev/null", "/dev/stderr", "/dev/stdout", "&1", "&2"):
                    continue
                cls = classify_secret_path(tgt, ctx)
                if cls:
                    out.append(Decision(ASK, "secret-file", "Writing to %s, a secrets file." % tgt))
                out.extend(check_config_write(tgt, ctx, "Bash redirection"))
        if prog in WRITE_PROGRAMS or (prog in ("sed", "perl") and any(a.startswith("-i") for a in args)):
            for raw in flag_value_paths(args):
                if path_like(raw):
                    out.extend(check_config_write(raw, ctx, prog))

        # --- secrets: programs and subcommands that print credentials ---
        if prog in SECRET_PROGRAMS and nonflags and nonflags[0] in ("show", "get", "ls", "list", "lookup", "search", "export", "cat"):
            out.append(Decision(DENY, "secret-read", "Password manager reads are off limits."))
        if prog in CLOUD_CLIS | {"gh", "git", "security", "npm", "op", "doppler", "vault", "kubectl", "heroku", "railway"}:
            joined = " ".join(a for a in args if a not in ("alpha", "beta"))
            for sc in SECRET_SUBCOMMANDS:
                if re.search(r"(?<![\w-])" + re.escape(sc) + r"(?![\w-])", joined):
                    if sc in ("read", "variables", "secrets") and prog not in ("vault", "railway", "doppler", "op", "fly", "flyctl", "wrangler", "supabase"):
                        continue
                    if sc == "read" and prog != "vault" and not (prog == "op"):
                        continue
                    if sc == "output -json" and prog not in ("terraform", "tofu"):
                        continue
                    if sc == "show -json" and prog not in ("terraform", "tofu"):
                        continue
                    if sc in ("get secret", "get secrets", "describe secret") and prog not in ("kubectl", "oc"):
                        continue
                    if sc == "variables" and prog != "railway":
                        continue
                    if sc == "secrets" and prog != "doppler":
                        continue
                    if sc == "token create" and prog != "npm":
                        continue
                    out.append(Decision(DENY, "secret-read", "`%s %s` prints or mints credentials. The guard keeps secrets out of the transcript." % (prog, sc)))
                    break

        # --- shells and interpreters: recurse / scan inline code ---
        if prog in SHELLS and "-c" in args:
            inner = args[args.index("-c") + 1] if args.index("-c") + 1 < len(args) else ""
            out.extend(check_bash(inner, ctx, depth + 1))
        if prog == "eval" and args:
            out.extend(check_bash(" ".join(args), ctx, depth + 1))
        if prog == "ssh" and nonflags:
            remote_cmd = " ".join(nonflags[1:])
            if remote_cmd:
                out.extend(check_bash(remote_cmd, ctx, depth + 1))
            host = nonflags[0]
            if cfg.is_prod(host) or cfg.is_prod(seg):
                out.append(Decision(DENY if remote_cmd else ASK, "prod-ssh", "SSH to a production host."))
            else:
                out.append(Decision(ASK, "remote-shell", "Shell access to a remote host."))
        if prog in INTERPRETERS:
            code = ""
            for flag in ("-c", "-e", "--eval", "-p", "-r"):
                if flag in args and args.index(flag) + 1 < len(args):
                    code = args[args.index(flag) + 1]
                    break
            if code:
                if DESTRUCTIVE_CODE_RE.search(code):
                    out.append(Decision(DENY, "delete-code", "Inline code deletes files. Deletes must be reversible: move to trash instead."))
                if ENV_DUMP_CODE_RE.search(code):
                    out.append(Decision(DENY, "secret-env", "Inline code dumps the whole environment, which holds credentials."))
                for m in ENV_SECRET_CODE_RE.finditer(code):
                    if SECRET_ENV_NAME_RE.search(m.group(1)):
                        out.append(Decision(DENY, "secret-env", "Inline code reads $%s, which looks like a credential." % m.group(1)))
                        break
            if prog in ("python", "python3") and args and args[0] == "-" :
                pass

        # --- deletes on the filesystem ---
        if prog in ("rm", "unlink"):
            out.append(check_rm(args, ctx))
        if prog in ("shred", "srm", "wipe"):
            out.append(Decision(DENY, "delete", "Secure-erase is the opposite of reversible."))
        if prog == "find" and ("-delete" in args):
            out.append(Decision(DENY, "delete", "`find -delete` is not reversible. Use %s instead." % trash_hint(ctx)))
        if prog == "find" and any(a in ("-exec", "-execdir", "-ok", "-okdir") for a in args):
            idx = next(i for i, a in enumerate(args) if a in ("-exec", "-execdir", "-ok", "-okdir"))
            sub = args[idx + 1:]
            end = next((i for i, a in enumerate(sub) if a in (";", "+")), len(sub))
            if sub[:end]:
                out.extend(check_bash(" ".join(shlex.quote(x) for x in sub[:end]), ctx, depth + 1))
        if prog == "mv" and nonflags and nonflags[-1] == "/dev/null":
            out.append(Decision(DENY, "delete", "Moving to /dev/null is a delete."))
        if prog in ("truncate",) and any(a in ("-s", "--size") for a in args) and re.search(r"(?:-s|--size)\s*=?\s*0\b", seg):
            out.append(Decision(ASK, "delete", "Truncating a file to zero discards its contents."))

        # --- git ---
        if prog == "git":
            d, simulated_branch = check_git(args, ctx, simulated_branch)
            out.extend(d)
        if prog == "gh":
            out.extend(check_gh(args, seg, ctx))

        # --- package registries ---
        if prog in ("npm", "yarn", "pnpm", "bun") and nonflags:
            if nonflags[0] in ("unpublish", "deprecate") or (nonflags[0] == "owner" and "rm" in nonflags) or (nonflags[0] == "dist-tag" and "rm" in nonflags):
                out.append(Decision(DENY, "registry-delete", "Removing or deprecating published packages is not reversible."))
            elif nonflags[0] == "publish" or (nonflags[0] == "npm" and "publish" in nonflags):
                out.append(Decision(ASK, "outward", "Publishing a package is public and permanent."))
        if (prog == "twine" and "upload" in nonflags) or (prog == "cargo" and "publish" in nonflags) or (prog == "gem" and "push" in nonflags) or (prog == "poetry" and "publish" in nonflags) or (prog == "mvn" and "deploy" in nonflags):
            out.append(Decision(ASK, "outward", "Publishing a package is public and permanent."))
        if prog == "cargo" and "yank" in nonflags:
            out.append(Decision(DENY, "registry-delete", "Yanking a crate is not reversible."))

        # --- docker ---
        if prog in ("docker", "podman", "nerdctl", "docker-compose"):
            out.extend(check_docker(args, nonflags, seg, ctx))

        # --- databases ---
        if prog in DB_CLIS or prog in DUMP_CLIS:
            out.extend(check_db(prog, args, nonflags, whole, seg, ctx))
        if prog in ("dropdb", "dropuser"):
            out.append(Decision(DENY, "db-destroy", "Dropping a database or role is not reversible."))
        if prog == "createdb":
            out.append(Decision(ASK, "db-write", "Creating a database."))
        if prog in ("pg_restore", "mysqlimport", "mongorestore", "mongoimport"):
            out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "db-write", "Restoring data into a database overwrites what is there."))
        if prog in ("prisma", "npx") and "prisma" in toks:
            j = " ".join(toks)
            if re.search(r"migrate\s+reset|--force-reset|db\s+drop", j):
                out.append(Decision(DENY, "db-destroy", "Prisma reset drops the database."))
            elif re.search(r"migrate\s+deploy|db\s+push|db\s+seed|db\s+execute|migrate\s+dev", j):
                out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "db-write", "Schema or data change through Prisma."))
        if prog in ("rails", "rake", "bin/rails") or (toks[0].endswith("/rails")):
            j = " ".join(args)
            if re.search(r"db:(?:drop|reset|purge|schema:load|truncate_all)", j):
                out.append(Decision(DENY, "db-destroy", "This drops or wipes the database."))
            elif re.search(r"db:(?:migrate|seed|rollback)", j):
                out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "db-write", "Database migration or seed."))
        if (prog in ("python", "python3") and args and args[0].endswith("manage.py")) or prog == "manage.py":
            j = " ".join(args)
            if re.search(r"\b(?:flush|sqlflush|reset_db)\b", j):
                out.append(Decision(DENY, "db-destroy", "Django flush wipes all tables."))
            elif re.search(r"\bmigrate\b|\bloaddata\b", j):
                out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "db-write", "Database migration or data load."))
        if prog in ("alembic", "knex", "flyway", "liquibase", "goose", "dbmate", "sqitch", "drizzle-kit", "atlas", "sequelize", "sequelize-cli", "typeorm", "diesel", "sqlx"):
            j = " ".join(args)
            if re.search(r"\b(?:drop|reset|rollback:all|db:drop|clean|baseline)\b", j):
                out.append(Decision(DENY, "db-destroy", "This drops or resets the database."))
            elif re.search(r"\b(?:upgrade|downgrade|migrate|push|deploy|run|up|down|rollback|latest|seed|apply)\b", j):
                out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "db-write", "Database migration."))

        # --- cloud CLIs ---
        if prog in CLOUD_CLIS:
            out.extend(check_cloud(prog, args, nonflags, seg, whole, ctx))

        # --- HTTP ---
        if prog in HTTP_CLIS:
            out.extend(check_http(prog, args, seg, ctx))
        if prog in ("scp", "rsync", "sftp", "ftp", "lftp"):
            if prog == "rsync" and any(a.startswith("--delete") or a == "--remove-source-files" for a in args):
                out.append(Decision(DENY, "delete", "rsync --delete removes files with no undo."))
            remote = [a for a in nonflags if re.match(r"^(?:[\w.-]+@)?[\w.-]+:", a) or "://" in a]
            if remote:
                if remote[-1] == nonflags[-1] if nonflags else False:
                    out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "remote-write", "Copying files to a remote host."))
            elif prog in ("sftp", "ftp", "lftp"):
                out.append(Decision(ASK, "remote-shell", "Interactive file transfer session."))

        # --- misc system ---
        if prog in ("apt", "apt-get", "yum", "dnf", "pacman", "brew", "apk", "zypper", "snap") and nonflags:
            if nonflags[0] in ("remove", "purge", "autoremove", "uninstall", "erase") or (prog == "pacman" and any(a.startswith("-R") for a in args)):
                out.append(Decision(ASK, "system-remove", "Removing system packages."))
        if prog in ("pip", "pip3", "pipx", "npm", "gem", "cargo") and nonflags and nonflags[0] in ("uninstall", "remove", "rm", "un", "r") and ("-g" in args or "--global" in args or prog in ("pipx", "gem")):
            out.append(Decision(ASK, "system-remove", "Removing a globally installed package."))
        if prog in ("launchctl", "systemctl", "service") and nonflags and nonflags[0] in ("stop", "disable", "mask", "unload", "bootout", "kill"):
            out.append(Decision(ASK, "system-service", "Stopping or disabling a system service."))
        if prog in ("dd",) and any(a.startswith("of=") and not a.startswith("of=/dev/null") for a in args):
            out.append(Decision(ASK, "overwrite", "dd overwrites its target in place."))
        if prog in ("vim", "vi", "nano", "emacs", "less", "more", "top", "htop") and not nonflags and prog in ("top", "htop"):
            pass

    return out


def trash_hint(ctx):
    root = ctx.cfg.plugin_root
    if root:
        return "`%s/bin/drip-trash <paths>`" % root
    return "drip-trash (ships with drip-guardrails)"


def check_rm(args, ctx):
    cfg = ctx.cfg
    paths = []
    after_dashdash = False
    for a in args:
        if a == "--" and not after_dashdash:
            after_dashdash = True
            continue
        if a.startswith("-") and not after_dashdash:
            continue
        paths.append(a)
    danger = {"/", "~", "/*", "~/", "*", ".", "..", "$HOME", "${HOME}", "/home", "/Users", "/etc", "/usr", "/var"}
    for p in paths:
        if p.strip("'\"") in danger or norm_path(p, ctx) in ("/", cfg.home, "/home", "/Users", "/etc", "/usr", "/var", "/opt", "/bin", "/sbin", "/lib"):
            return Decision(DENY, "delete", "Refusing to delete %s." % p)
    if cfg.rm_strict:
        return Decision(DENY, "delete", "Deletes must be reversible. Use %s; it moves files to %s and prints how to restore them." % (trash_hint(ctx), cfg.trash_dir))
    if not paths:
        return Decision(DENY, "delete", "rm with an unresolved target. Deletes must be reversible: use %s." % trash_hint(ctx))
    allowed_prefixes = [norm_path(p, ctx) for p in cfg.rm_allow] + ["/tmp", "/var/tmp", "/private/tmp", "/dev/shm", os.environ.get("TMPDIR", "/nonexistent").rstrip("/"), posixpath.join(cfg.home, ".cache"), posixpath.join(cfg.home, ".npm/_cacache")]
    ephemeral = {"node_modules", "dist", "build", "out", ".next", ".nuxt", ".cache", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage", "target", ".turbo", ".parcel-cache", ".venv", "venv", ".tox", ".gradle", "tmp", "temp", ".tmp", "vendor", "Pods", "DerivedData", ".terraform", ".serverless", "htmlcov", ".eggs", "site-packages", "bower_components", ".svelte-kit", ".angular", ".output", "storybook-static"}
    ok = True
    for p in paths:
        full = norm_path(p, ctx)
        if any(full == pre or full.startswith(pre + "/") for pre in allowed_prefixes if pre):
            continue
        parts = [x for x in full.split("/") if x]
        if any(x in ephemeral for x in parts) or (parts and (parts[-1].endswith((".log", ".tmp", ".pyc", ".o", ".class", ".swp", ".orig", ".rej", ".DS_Store", ".bak~", "~")))):
            continue
        if re.search(r"(?:^|/)\.?(?:tmp|temp|cache|scratch)[^/]*(?:/|$)", full):
            continue
        ok = False
        break
    if ok:
        return allow()
    return Decision(DENY, "delete", "Deletes must be reversible. Use %s instead; it moves files to %s and prints how to restore them. (Build artefacts, caches and temp files may still be rm'd.)" % (trash_hint(ctx), cfg.trash_dir))


def check_config_write(raw, ctx, via):
    cfg = ctx.cfg
    out = []
    full = norm_path(raw, ctx)
    home = cfg.home.rstrip("/")
    root = cfg.plugin_root.rstrip("/")
    if root and (full == root or full.startswith(root + "/")):
        out.append(Decision(DENY, "self-protect", "The guard does not modify its own files (%s)." % via))
        return out
    if "/drip-guardrails/" in full + "/" and "/.claude/plugins/" in full:
        out.append(Decision(DENY, "self-protect", "The guard does not modify its own installed files."))
        return out
    if full.startswith(posixpath.join(home, ".claude/plugins") + "/"):
        out.append(Decision(DENY, "self-protect", "Installed plugins are managed by `claude plugin`, not edited in place."))
        return out
    if full.endswith(CONFIG_PATH_SUFFIXES) or any(s + "/" in full for s in CONFIG_PATH_SUFFIXES if s.endswith(("hooks", "agents", "commands"))):
        out.append(Decision(ASK, "self-config", "Editing Claude Code settings or hooks (%s) changes what the agent is allowed to do." % posixpath.basename(full)))
    elif full == posixpath.join(home, ".ssh/authorized_keys"):
        out.append(Decision(DENY, "persistence", "authorized_keys grants login access. Not writable."))
    elif posixpath.basename(full) in PERSISTENCE_BASENAMES and full.startswith(home + "/"):
        out.append(Decision(ASK, "persistence", "Editing a shell start-up file persists beyond this session."))
    elif full.startswith(("/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/boot/", "/System/", "/Library/", "/private/etc/")):
        out.append(Decision(ASK, "system-write", "Writing to a system path."))
    return out


def check_git(args, ctx, simulated_branch):
    cfg = ctx.cfg
    out = []
    i = 0
    gitdir = None
    while i < len(args) and args[i].startswith("-"):
        if args[i] in ("-C", "-c", "--git-dir", "--work-tree") and i + 1 < len(args):
            if args[i] == "-C":
                gitdir = args[i + 1]
            i += 2
        else:
            i += 1
    if i >= len(args):
        return out, simulated_branch
    sub = args[i]
    rest = args[i + 1:]
    nonflags = [a for a in rest if not a.startswith("-")]
    cwd = norm_path(gitdir, ctx) if gitdir else ctx.cwd

    if sub in ("checkout", "switch"):
        target = None
        for k, a in enumerate(rest):
            if a in ("-b", "-B", "-c", "-C") and k + 1 < len(rest):
                target = rest[k + 1]
                break
        if target is None and nonflags and "--" not in rest:
            target = nonflags[0]
        if target:
            simulated_branch = target
        if sub == "checkout" and ("--" in rest or (nonflags and nonflags == ["."])) or (sub == "checkout" and nonflags and nonflags[0] == "." ):
            out.append(Decision(ASK, "discard-changes", "This discards uncommitted changes, which have no undo."))
    if sub == "restore" and "--staged" not in rest and "-S" not in rest:
        out.append(Decision(ASK, "discard-changes", "git restore discards uncommitted changes, which have no undo."))
    if sub == "reset" and ("--hard" in rest or "--merge" in rest):
        out.append(Decision(ASK, "discard-changes", "git reset --hard discards uncommitted work. Commits stay in the reflog, uncommitted changes do not."))
    if sub == "clean" and not any(a in ("-n", "--dry-run") for a in rest) and any(a.startswith("-") and ("f" in a or a == "--force") for a in rest):
        out.append(Decision(DENY, "delete", "git clean deletes untracked files for good. Use `git clean -n` to list them and %s to remove them." % trash_hint(ctx)))
    if sub == "branch" and any(a in ("-D",) or (a.startswith("-") and "D" in a and not a.startswith("--")) for a in rest):
        out.append(Decision(DENY, "delete", "Force-deleting a branch loses unmerged commits. `git branch -d` is fine for merged ones."))
    if sub == "branch" and ("--delete" in rest and "--force" in rest):
        out.append(Decision(DENY, "delete", "Force-deleting a branch loses unmerged commits."))
    if sub == "stash" and nonflags and nonflags[0] in ("drop", "clear"):
        out.append(Decision(DENY, "delete", "Dropping stashes is not reversible."))
    if sub == "reflog" and nonflags and nonflags[0] in ("expire", "delete"):
        out.append(Decision(DENY, "delete", "The reflog is the undo buffer. It stays."))
    if sub == "gc" and any(a.startswith("--prune") or a == "--aggressive" for a in rest):
        out.append(Decision(DENY, "delete", "Pruning unreachable objects removes the undo buffer."))
    if sub in ("prune", "filter-branch", "filter-repo", "replace") or (sub == "update-ref" and "-d" in rest):
        out.append(Decision(DENY, "history-rewrite", "History rewriting and ref deletion are not reversible."))
    if sub == "worktree" and nonflags and nonflags[0] == "remove" and any(a in ("-f", "--force") for a in rest):
        out.append(Decision(DENY, "delete", "Force-removing a worktree discards its uncommitted changes."))
    if sub == "tag" and any(a in ("-d", "--delete") for a in rest):
        out.append(Decision(ASK, "delete", "Deleting a local tag."))
    if sub == "config" and ("--global" in rest or "--system" in rest) and nonflags:
        out.append(Decision(ASK, "persistence", "Global git config change persists beyond the session."))
    if sub == "remote" and nonflags and nonflags[0] in ("remove", "rm", "set-url", "prune"):
        out.append(Decision(ASK, "git-remote", "Changing remotes."))
    if sub == "credential" and nonflags and nonflags[0] == "fill":
        out.append(Decision(DENY, "secret-read", "git credential fill prints stored passwords."))
    if sub == "add":
        secret_hits = []
        for a in nonflags:
            if classify_secret_path(a, ctx) == DENY:
                secret_hits.append(a)
        if secret_hits:
            out.append(Decision(DENY, "secret-file", "Staging %s would commit secrets." % ", ".join(secret_hits)))
        elif any(a in ("-A", "--all", ".", "*") for a in rest) or any(a == "." for a in nonflags):
            listing = ctx.runner.run(["git", "ls-files", "--others", "--exclude-standard"], cwd=cwd) or ""
            hits = [f for f in listing.splitlines() if classify_secret_path(f, ctx) == DENY]
            if hits:
                out.append(Decision(DENY, "secret-file", "`git add -A` would stage untracked secret files: %s. Add them to .gitignore first." % ", ".join(hits[:5])))
    if sub == "push":
        out.extend(check_git_push(rest, nonflags, ctx, cwd, simulated_branch))
    if sub == "merge" and nonflags:
        cur = simulated_branch or current_branch(ctx, cwd)
        if cfg.is_protected_branch(cur):
            out.append(Decision(DENY, "protected-branch", "Merging into %s locally is how merges reach a protected branch. Open a pull request instead." % cur))
    if sub in ("commit",) and ("--no-verify" in rest or "-n" in rest):
        out.append(Decision(ASK, "skip-hooks", "--no-verify skips the repository's own commit checks."))
    return out, simulated_branch


def current_branch(ctx, cwd):
    out = ctx.runner.run(["git", "symbolic-ref", "--short", "HEAD"], cwd=cwd)
    return (out or "").strip()


def check_git_push(rest, nonflags, ctx, cwd, simulated_branch):
    cfg = ctx.cfg
    out = []
    force = any(a in ("-f", "--force") or (a.startswith("-") and not a.startswith("--") and "f" in a) for a in rest)
    lease = any(a.startswith("--force-with-lease") or a == "--force-if-includes" for a in rest)
    delete = any(a in ("-d", "--delete") for a in rest)
    if "--no-verify" in rest:
        out.append(Decision(ASK, "skip-hooks", "--no-verify skips the repository's own push checks."))
    if any(a in ("--mirror",) for a in rest):
        out.append(Decision(DENY, "protected-branch", "A mirror push rewrites every ref on the remote."))
    if "--all" in rest:
        out.append(Decision(ASK, "protected-branch", "Pushing all branches may include protected ones."))
    positional = [a for a in rest if not a.startswith("-")]
    # drop values of flags that take an argument
    for k, a in enumerate(rest):
        if a in ("-o", "--push-option", "--receive-pack", "--exec", "--repo") and k + 1 < len(rest) and rest[k + 1] in positional:
            positional.remove(rest[k + 1])
    refspecs = positional[1:] if positional else []
    targets = []
    for spec in refspecs:
        s = spec
        if s.startswith("+"):
            force = True
            s = s[1:]
        if ":" in s:
            src, dst = s.split(":", 1)
            if src == "":
                delete = True
            targets.append(dst)
        else:
            targets.append(s)
    if delete:
        out.append(Decision(DENY, "delete", "Deleting a remote branch or tag is not reversible from here."))
    if not refspecs:
        branch = simulated_branch or current_branch(ctx, cwd)
        targets.append(branch)
        if simulated_branch and cfg.is_protected_branch(simulated_branch):
            out.append(Decision(DENY, "protected-branch", "This command switches to %s and then pushes it." % simulated_branch))
    targets = [(simulated_branch or current_branch(ctx, cwd)) if t == "HEAD" else t for t in targets]
    for t in targets:
        if t and cfg.is_protected_branch(t):
            out.append(Decision(DENY, "protected-branch", "Pushing to %s is off. Push a feature branch and open a pull request." % t))
    if force and not lease:
        out.append(Decision(DENY, "force-push", "Force pushes rewrite shared history. If you must, --force-with-lease on your own branch asks for confirmation."))
    elif lease:
        if any(cfg.is_protected_branch(t) for t in targets if t):
            out.append(Decision(DENY, "force-push", "No force pushes to protected branches."))
        else:
            out.append(Decision(ASK, "force-push", "Force-with-lease rewrites the remote branch."))
    return out


def check_gh(args, seg, ctx):
    cfg = ctx.cfg
    out = []
    nonflags = [a for a in args if not a.startswith("-")]
    j = " ".join(args)
    if len(nonflags) >= 2 and nonflags[0] == "pr" and nonflags[1] == "merge":
        out.append(Decision(DENY, "no-merge", "Merging pull requests is a human decision. Leave the PR ready and say so."))
    if nonflags[:2] == ["pr", "review"] and ("--approve" in args or "-a" in args):
        out.append(Decision(DENY, "no-approve", "Approvals count toward merge. The agent does not approve pull requests."))
    if nonflags[:2] == ["pr", "review"] or nonflags[:2] == ["pr", "comment"] or nonflags[:2] == ["issue", "comment"]:
        out.append(Decision(ASK, "outward", "Posting on GitHub notifies people."))
    if nonflags[:2] in (["repo", "delete"], ["release", "delete"], ["issue", "delete"], ["secret", "delete"], ["variable", "delete"], ["cache", "delete"], ["label", "delete"], ["codespace", "delete"], ["gist", "delete"], ["run", "delete"], ["ssh-key", "delete"], ["gpg-key", "delete"], ["workflow", "disable"]):
        out.append(Decision(DENY, "delete", "GitHub deletes are not reversible from here."))
    if nonflags[:2] in (["repo", "archive"], ["pr", "close"], ["issue", "close"], ["run", "cancel"], ["repo", "create"], ["repo", "fork"], ["release", "create"], ["workflow", "run"], ["secret", "set"], ["variable", "set"], ["repo", "edit"], ["pr", "ready"], ["pr", "lock"], ["issue", "lock"], ["issue", "transfer"]):
        out.append(Decision(ASK, "github-write", "GitHub write: `gh %s %s`." % (nonflags[0], nonflags[1])))
    if nonflags[:2] == ["auth", "token"] or (nonflags[:2] == ["auth", "status"] and ("--show-token" in args or "-t" in args)):
        out.append(Decision(DENY, "secret-read", "gh auth token prints a credential."))
    if nonflags[:1] == ["api"]:
        method = "GET"
        for k, a in enumerate(args):
            if a in ("-X", "--method") and k + 1 < len(args):
                method = args[k + 1].upper()
            elif a.startswith("--method="):
                method = a.split("=", 1)[1].upper()
        if method == "GET" and any(a in ("-f", "-F", "--field", "--raw-field", "--input") or a.startswith(("--field=", "--raw-field=", "--input=")) for a in args):
            method = "POST"
        path = nonflags[1] if len(nonflags) > 1 else ""
        if method == "GET":
            pass
        elif re.search(r"/merge(?:s|$|\?)|mergePullRequest|enablePullRequestAutoMerge|merge_method", path + " " + j):
            out.append(Decision(DENY, "no-merge", "Merging pull requests is a human decision."))
        elif method == "DELETE" or re.search(r"\bdelete\w*\s*\(", j):
            out.append(Decision(DENY, "delete", "GitHub API deletes are not reversible from here."))
        elif re.search(r"\bAPPROVE\b|addPullRequestReview\b.*APPROVE", j):
            out.append(Decision(DENY, "no-approve", "The agent does not approve pull requests."))
        elif re.search(r"/git/refs/heads/|/contents/", path) and any(cfg.is_protected_branch(b) for b in re.findall(r"(?:refs/heads/|branch=|\"branch\":\s*\")([\w./-]+)", j)):
            out.append(Decision(DENY, "protected-branch", "Writing to a protected branch through the API."))
        else:
            out.append(Decision(ASK, "github-write", "GitHub API write (%s %s)." % (method, path)))
    return out


def check_docker(args, nonflags, seg, ctx):
    cfg = ctx.cfg
    out = []
    j = " ".join(nonflags[:3])
    if re.match(r"^(?:volume (?:rm|prune)|system prune|builder prune|image prune|container prune|network prune)", j) or (nonflags[:2] == ["system", "prune"]) or ("--volumes" in args and "prune" in nonflags) or (nonflags[:2] == ["compose", "down"] and any(a in ("-v", "--volumes") for a in args)) or (nonflags[:1] == ["down"] and any(a in ("-v", "--volumes") for a in args)):
        out.append(Decision(DENY, "delete", "Removing Docker volumes or pruning deletes data with no undo."))
    elif nonflags[:1] in (["rm"], ["rmi"]) or nonflags[:2] in (["container", "rm"], ["image", "rm"], ["network", "rm"], ["stack", "rm"], ["service", "rm"], ["secret", "rm"], ["context", "rm"]):
        out.append(Decision(ASK, "docker-remove", "Removing containers or images. Rebuildable, but confirm."))
    if nonflags[:1] == ["push"] or nonflags[:2] == ["image", "push"]:
        out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "outward", "Pushing an image to a registry."))
    if nonflags[:1] in (["login"],):
        out.append(Decision(ASK, "auth", "Docker registry login."))
    if nonflags[:1] == ["stack"] and nonflags[1:2] == ["deploy"]:
        out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "deploy", "Deploying a Docker stack."))
    if "-H" in args or any(a.startswith("--host") or a.startswith("--context") for a in args) or "DOCKER_HOST=" in seg:
        if nonflags and nonflags[0] not in ("ps", "images", "logs", "inspect", "version", "info", "stats", "top", "events", "port", "diff", "history"):
            out.append(Decision(DENY if cfg.is_prod(seg) else ASK, "remote-write", "Docker command against a remote daemon."))
    return out


def check_db(prog, args, nonflags, whole, seg, ctx):
    cfg = ctx.cfg
    out = []
    prod = cfg.is_prod(seg) or cfg.is_prod(whole)
    if prog in DUMP_CLIS and not (prog == "sqlite3" and ".dump" not in whole):
        out.append(Decision(ASK, "bulk-export", "Dumping a database copies all of its data, which may include personal data."))
        if prog != "sqlite3":
            return out
    if prog == "bq" and nonflags[:1] != ["query"]:
        return out
    text = whole
    if SQL_DESTROY_RE.search(text):
        out.append(Decision(DENY, "db-destroy", "DROP, TRUNCATE, DELETE and friends are not reversible. Soft-delete or take a backup and ask a human."))
        return out
    if SQL_WRITE_RE.search(text):
        out.append(Decision(DENY if prod else ASK, "db-write", "This statement writes to the database%s." % (" and the target looks like production" if prod else "")))
        return out
    reads_file = any(a in ("-f", "--file", "--eval-file", "-i", "--init") for a in args) or re.search(r"<\s*\S+\.(?:sql|js|cql)\b", seg)
    has_inline = any(a in ("-c", "--command", "-e", "--execute", "--eval", "-q", "--query", "-Q") for a in args) or re.search(r"(?:^|\|)\s*(?:echo|printf|cat)\b", whole) or "<<" in whole
    if reads_file:
        out.append(Decision(DENY if prod else ASK, "db-opaque", "The SQL comes from a file the guard cannot see."))
    elif not has_inline and prog not in ("bq",) and not nonflags[:1] in (["--version"],):
        if prog in ("redis-cli",) and nonflags and nonflags[0].upper() in ("GET", "MGET", "HGET", "HGETALL", "KEYS", "SCAN", "LRANGE", "SMEMBERS", "ZRANGE", "TTL", "EXISTS", "INFO", "PING", "DBSIZE", "TYPE", "LLEN", "SCARD", "ZCARD", "HKEYS", "HLEN", "STRLEN", "CLIENT", "MONITOR"):
            return out
        if prog == "redis-cli" and nonflags:
            out.append(Decision(DENY if prod else ASK, "db-write", "Redis command `%s` writes." % nonflags[0]))
            return out
        if prog in ("psql", "mysql", "mariadb", "mongosh", "mongo", "sqlite3", "pgcli", "mycli", "litecli", "duckdb", "cqlsh", "usql", "clickhouse-client", "sqlcmd", "snowsql", "cockroach", "turso", "pscale") and prod:
            out.append(Decision(ASK, "db-opaque", "Interactive session against what looks like a production database."))
    return out


def check_cloud(prog, args, nonflags, seg, whole, ctx):
    cfg = ctx.cfg
    out = []
    toks = [a for a in nonflags if a not in ("alpha", "beta", "preview", "--")]
    lowered = [t.lower() for t in toks]
    prod = cfg.is_prod(seg) or cfg.is_prod(whole) or env_is_prod(prog, args, seg, ctx)

    # SQL handed to a cloud CLI (wrangler d1, gcloud sql, turso, ...)
    if SQL_DESTROY_RE.search(seg):
        out.append(Decision(DENY, "cloud-destroy", "That statement drops or deletes data. Not reversible."))
        return out

    if prog in ("terraform", "tofu"):
        if "destroy" in lowered or ("apply" in lowered and any(a in ("-destroy", "--destroy") for a in args)) or lowered[:2] == ["state", "rm"] or lowered[:2] == ["workspace", "delete"]:
            out.append(Decision(DENY, "cloud-destroy", "terraform destroy / state rm is not reversible."))
        elif lowered[:1] in (["apply"], ["import"], ["taint"], ["untaint"]) or lowered[:2] in (["state", "mv"], ["state", "push"], ["state", "replace-provider"]) or "force-unlock" in lowered:
            if "apply" in lowered and any(a in ("-auto-approve", "--auto-approve") for a in args):
                out.append(Decision(DENY if prod else ASK, "cloud-write", "terraform apply without a plan review."))
            else:
                out.append(Decision(DENY if prod else ASK, "cloud-write", "terraform %s changes real infrastructure." % lowered[0]))
        return out
    if prog == "pulumi":
        if lowered[:1] == ["destroy"] or lowered[:2] == ["stack", "rm"]:
            out.append(Decision(DENY, "cloud-destroy", "pulumi destroy is not reversible."))
        elif lowered[:1] in (["up"], ["refresh"], ["import"]) or lowered[:2] == ["state", "delete"]:
            out.append(Decision(DENY if prod else ASK, "cloud-write", "pulumi %s changes real infrastructure." % lowered[0]))
        return out
    if prog in ("gsutil",):
        if lowered[:1] in (["rm"], ["rb"]) or ("rsync" in lowered and any(a in ("-d", "--delete-unmatched-destination-objects") for a in args)) or lowered[:1] == ["mv"]:
            out.append(Decision(DENY, "cloud-destroy", "Deleting bucket objects is not reversible unless versioning is on. Treat it as not."))
        elif lowered[:1] in (["cp"], ["rsync"]) and toks and toks[-1].startswith("gs://"):
            out.append(Decision(DENY if prod else ASK, "cloud-write", "Uploading to a bucket."))
        elif lowered and lowered[0] in ("acl", "iam", "defacl", "cors", "lifecycle", "versioning", "web", "notification", "label", "retention", "kms", "setmeta", "compose", "mb"):
            out.append(Decision(DENY if prod else ASK, "cloud-write", "Bucket configuration change."))
        return out
    if prog in ("aws",):
        if lowered[:2] in (["s3", "rm"], ["s3", "rb"]) or (lowered[:2] == ["s3", "sync"] and "--delete" in args) or lowered[:2] == ["s3", "mv"]:
            out.append(Decision(DENY, "cloud-destroy", "Deleting S3 objects is not reversible."))
            return out
        if lowered[:2] in (["s3", "cp"], ["s3", "sync"]) and toks and toks[-1].startswith("s3://"):
            out.append(Decision(DENY if prod else ASK, "cloud-write", "Uploading to S3."))
            return out
        if lowered[:2] in (["s3", "cp"], ["s3", "sync"], ["s3", "ls"], ["s3", "presign"]):
            return out
    if prog == "vercel" and lowered[:2] == ["env", "pull"]:
        out.append(Decision(DENY, "secret-read", "vercel env pull writes production secrets to a local file."))
        return out
    if prog == "heroku" and lowered[:1] == ["config"]:
        out.append(Decision(DENY, "secret-read", "heroku config prints every config var, including secrets."))
        return out
    if prog == "supabase" and lowered[:2] == ["db", "reset"]:
        remote = any(a in ("--linked", "--db-url") or a.startswith("--db-url=") for a in args)
        out.append(Decision(DENY if remote else ASK, "cloud-destroy" if remote else "db-destroy", "Resetting the %s database." % ("linked remote" if remote else "local")))
        return out
    if prog == "vault" and lowered[:1] in (["read"], ["kv"]) and (lowered[:1] == ["read"] or lowered[1:2] == ["get"]):
        out.append(Decision(DENY, "secret-read", "Vault reads print secrets."))
        return out
    if prog in ("kubectl", "oc"):
        if lowered[:1] == ["delete"] or (lowered[:1] == ["drain"]):
            out.append(Decision(DENY, "cloud-destroy", "kubectl delete is not reversible."))
            return out
        if lowered[:1] in (["get"], ["describe"]) and len(lowered) > 1 and lowered[1] in ("secret", "secrets") or (lowered[:1] == ["get"] and any(t.startswith("secret/") or t.startswith("secrets/") for t in lowered)):
            out.append(Decision(DENY, "secret-read", "Kubernetes secrets are base64, not encrypted. Not readable."))
            return out
        if lowered[:1] == ["exec"]:
            out.append(Decision(DENY if prod else ASK, "remote-shell", "Shell inside a pod."))
            return out
        if lowered[:1] == ["cp"] and toks and ":" in toks[-1]:
            out.append(Decision(DENY if prod else ASK, "cloud-write", "Copying files into a pod."))
            return out
    if prog == "helm" and lowered[:1] in (["uninstall"], ["delete"]):
        out.append(Decision(DENY, "cloud-destroy", "helm uninstall removes the release."))
        return out
    if prog == "gh":
        return out
    if prog in ("ansible", "ansible-playbook"):
        out.append(Decision(DENY if prod else ASK, "cloud-write", "Ansible runs change hosts."))
        return out
    if prog == "ngrok" or prog == "cloudflared":
        out.append(Decision(ASK, "exposure", "Exposing a local port to the internet."))
        return out

    # Generic classifier
    verb = None
    for t in lowered:
        if t in DESTROY_VERBS or t.startswith(DESTROY_PREFIXES) or re.match(r"^\w+:(?:destroy|delete|remove|rm|purge|reset|unset|flush)$", t):
            verb = "destroy"
            break
    if verb is None:
        for t in lowered:
            if t in WRITE_VERBS or t.startswith(WRITE_PREFIXES) or re.match(r"^\w+:(?:set|create|add|deploy|push|promote|scale|restart|run|rollback|update|enable|disable|import|attach|detach|migrate|upgrade|open|release|transfer|rename)$", t):
                verb = "write"
                break
    if verb == "destroy":
        if prog in ("gcloud",) and lowered[:2] == ["config", "unset"]:
            out.append(Decision(ASK, "cloud-config", "Changing local gcloud configuration."))
        elif prog == "aws" and any(t.startswith("remove-tags") or t == "untag-resource" for t in lowered):
            out.append(Decision(DENY if prod else ASK, "cloud-write", "Removing tags."))
        else:
            out.append(Decision(DENY, "cloud-destroy", "`%s %s` deletes a resource. Deletes must be reversible; disable or snapshot it and ask a human." % (prog, " ".join(toks[:3]))))
    elif verb == "write":
        if prog in ("gcloud", "aws", "az", "fly", "flyctl", "vercel", "heroku", "railway", "netlify", "doctl", "kubectl", "oc", "wrangler", "supabase", "firebase") and lowered[:2] in (["config", "set"], ["configure", "set"], ["config", "use-context"], ["config", "set-context"], ["config", "use"], ["use"], ["link"]) or (prog == "aws" and lowered[:1] == ["configure"]) or (prog in ("gcloud",) and lowered[:1] in (["auth"], ["components"], ["init"])) or (prog in ("az",) and lowered[:1] in (["login"], ["account"], ["configure"], ["extension"])):
            out.append(Decision(ASK, "cloud-config", "Changing local CLI configuration or authentication."))
        else:
            out.append(Decision(DENY if prod else ASK, "cloud-write", "`%s %s` writes to %s. Reads are fine; writes need a human%s." % (prog, " ".join(toks[:3]), "production" if prod else "a live system", "" if prod else ", or run it yourself")))
    return out


def env_is_prod(prog, args, seg, ctx):
    """Best-effort: does the CLI's active context point at production?"""
    cfg = ctx.cfg
    for k, a in enumerate(args):
        if a in ("--project", "--context", "--profile", "--cluster", "--namespace", "-n", "--app", "-a", "--env", "--environment", "--stage", "--subscription", "--workspace", "--stack", "--site", "--service", "--project-ref", "--region") and k + 1 < len(args):
            if cfg.is_prod(args[k + 1]):
                return True
        if "=" in a and a.startswith("--") and cfg.is_prod(a.split("=", 1)[1]):
            return True
    env = os.environ
    for name in ("AWS_PROFILE", "CLOUDSDK_CORE_PROJECT", "KUBECONFIG", "FLY_APP", "VERCEL_ENV", "NODE_ENV", "RAILS_ENV", "APP_ENV", "ENVIRONMENT", "STAGE", "AZURE_SUBSCRIPTION_ID"):
        if cfg.is_prod(env.get(name, "")):
            return True
    if prog in ("kubectl", "oc", "helm") and "--context" not in args:
        ctxname = ctx.runner.run(["kubectl", "config", "current-context"]) or ""
        if cfg.is_prod(ctxname):
            return True
    if prog in ("gcloud", "gsutil", "bq") and "--project" not in args:
        proj = ctx.runner.run(["gcloud", "config", "get-value", "project"]) or ""
        if cfg.is_prod(proj):
            return True
    return False


def check_http(prog, args, seg, ctx):
    cfg = ctx.cfg
    out = []
    method = "GET"
    body = False
    for k, a in enumerate(args):
        if a in ("-X", "--request") and k + 1 < len(args):
            method = args[k + 1].upper()
        elif a.startswith("--request=") or a.startswith("-X") and len(a) > 2:
            method = a.split("=", 1)[-1].upper() if "=" in a else a[2:].upper()
        elif a.startswith("--method="):
            method = a.split("=", 1)[1].upper()
        elif a in ("-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "-F", "--form", "--form-string", "-T", "--upload-file", "--json", "--post-data", "--post-file", "--body-data", "--body-file") or a.startswith(("--data", "--form", "--post-", "--body-", "--json=", "--upload-file=")):
            body = True
    if prog in ("http", "https", "xh", "httpie", "curlie"):
        for a in args:
            if a.upper() in ("POST", "PUT", "PATCH", "DELETE"):
                method = a.upper()
            if "=" in a and not a.startswith("-") and "://" not in a:
                body = True
    if method == "GET" and body:
        method = "POST"
    if any(a in ("-I", "--head", "-G", "--get") for a in args) and not any(a in ("-X", "--request") for a in args):
        method = "GET"
    hosts = URL_RE.findall(seg)
    local = all(LOCAL_HOST_RE.match(h.split("@")[-1]) for h in hosts) if hosts else False
    for a in args:
        if a.startswith("@") or (a.startswith("--data") and "@" in a) or (a.startswith("-") and "@" in a and prog == "curl"):
            p = a.split("@", 1)[1] if "@" in a else ""
            if p and classify_secret_path(p, ctx):
                out.append(Decision(DENY, "secret-file", "Uploading %s would send a secrets file off the machine." % p))
    if method in ("POST", "PUT", "PATCH", "DELETE") and not local:
        for m in SECRET_VAR_REF_RE.finditer(seg):
            if SECRET_ENV_NAME_RE.search(m.group(1)) and re.search(r"(?:-d|--data\S*|-F|--form|--json)\s+['\"]?[^'\"]*\$\{?%s\b" % re.escape(m.group(1)), seg):
                out.append(Decision(ASK, "secret-exfil", "A credential ($%s) is in the request body. Credentials belong in headers to their own API, nowhere else." % m.group(1)))
                break
        if method == "DELETE":
            out.append(Decision(DENY, "delete", "HTTP DELETE against a remote service is not reversible."))
        elif cfg.is_prod(seg) or any(cfg.is_prod(h) for h in hosts):
            out.append(Decision(DENY, "prod-write", "%s to what looks like a production endpoint." % method))
        elif cfg.http_writes == DENY:
            out.append(Decision(DENY, "http-write", "%s to %s." % (method, ", ".join(hosts) or "a remote host")))
        elif cfg.http_writes == ASK:
            out.append(Decision(ASK, "http-write", "%s to %s. Reads are free; writes get confirmed." % (method, ", ".join(hosts) or "a remote host")))
    if prog == "curl" and any(a in ("-o", "--output", "-O") for a in args):
        for k, a in enumerate(args):
            if a in ("-o", "--output") and k + 1 < len(args):
                out.extend(check_config_write(args[k + 1], ctx, "curl -o"))
    return out


# --------------------------------------------------------------------------
# Non-Bash built-in tools
# --------------------------------------------------------------------------

def check_read_tool(tool, inp, ctx):
    out = []
    for key in ("file_path", "path", "notebook_path", "pattern"):
        p = inp.get(key)
        if not isinstance(p, str) or not p:
            continue
        if key == "pattern" and tool == "Grep":
            continue
        if key == "pattern" and tool == "Glob":
            # a glob aimed straight at secret files
            base = posixpath.basename(p)
            if any(rx.match(base) for rx in _SECRET_DENY_RE) and "*" not in base:
                out.append(Decision(DENY, "secret-file", "Globbing for %s targets secret files." % p))
            continue
        cls = classify_secret_path(p, ctx)
        if cls == DENY:
            out.append(Decision(DENY, "secret-file", "%s holds secrets. The guard does not read it. Ask the user to provide what is needed through the environment or request_credential." % p))
        elif cls == ASK:
            out.append(Decision(ASK, "secret-file", "%s may contain secrets." % p))
    return out


def check_write_tool(tool, inp, ctx):
    out = []
    p = inp.get("file_path") or inp.get("notebook_path") or ""
    if isinstance(p, str) and p:
        cls = classify_secret_path(p, ctx)
        if cls:
            out.append(Decision(ASK, "secret-file", "Writing to %s, a secrets file. Values in it would be a copy of a secret." % p))
        out.extend(check_config_write(p, ctx, tool))
        base = posixpath.basename(p)
        if base in (".gitignore",) and tool == "Edit":
            old = inp.get("old_string") or ""
            new = inp.get("new_string") or ""
            if re.search(r"^\.env", old, re.M) and not re.search(r"^\.env", new, re.M):
                out.append(Decision(DENY, "secret-file", "Removing .env from .gitignore would let secrets be committed."))
    content = inp.get("content") or inp.get("new_string") or inp.get("new_source") or ""
    if isinstance(content, str) and content and DESTRUCTIVE_CODE_RE.search(content):
        out.append(Decision(ASK, "delete-code", "The written code deletes files. Fine for a tool that needs to, but confirm."))
    if isinstance(content, str) and re.search(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:/|~|\$HOME|\*)", content):
        out.append(Decision(DENY, "delete-code", "The written code removes the filesystem root or home directory."))
    return out


# --------------------------------------------------------------------------
# MCP tools
# --------------------------------------------------------------------------

MCP_DELETE_WORDS = {"delete", "remove", "destroy", "purge", "drop", "wipe", "clear", "erase", "truncate", "uninstall", "revoke", "unlink", "unset", "obliterate"}
MCP_REVERSIBLE_WORDS = {"trash", "archive", "unarchive", "disable", "unpublish", "unpin", "untrash", "unmark", "unsubscribe", "unwatch", "unresolve", "pause", "deactivate", "cancel", "interrupt", "stop", "mute"}
MCP_OUTWARD_WORDS = {"send", "reply", "forward", "publish", "share", "invite", "boost", "post", "notify", "mail", "deploy", "participate", "comment", "broadcast", "tweet", "respond", "request", "review"}
MCP_WRITE_WORDS = {"create", "update", "add", "set", "append", "insert", "write", "upload", "move", "copy", "rename", "merge", "push", "activate", "enable", "edit", "apply", "import", "attach", "label", "mark", "autofill", "resize", "generate", "register", "confirm", "connect", "disconnect", "select", "save", "fork", "trigger", "run", "execute", "invoke", "exec", "batch", "bulk", "sandbox", "put", "modify", "change", "assign", "transfer", "schedule", "reconnect", "tune", "switch", "pin", "subscribe", "watch", "resolve", "respond", "complete", "submit", "later", "fire", "autofill", "install", "tag", "retag"}
MCP_READ_WORDS = {"get", "list", "read", "search", "show", "describe", "fetch", "download", "query", "check", "help", "balance", "status", "preview", "render", "explore", "catalog", "resources", "resolve", "suggest", "wait", "display", "jobs", "transactions", "quote", "recipe", "presets", "instructions", "prepare", "guide", "export", "me", "members", "teams", "fields", "types", "collaborators", "options", "settings", "context", "brand", "feedback", "my", "tools", "diagnostics", "health", "recommendations", "stats", "quality", "errors", "benchmark", "trend", "signal", "score", "formats", "job", "readiness", "analysis", "predictor", "virality", "accounts", "listing", "dataset", "details", "summary", "info", "whoami", "ping", "version", "activity", "logs", "scanning", "eligibility", "sessions", "events", "environments", "repos", "triggers", "folders", "computer", "documentation", "formats"}

MCP_OVERRIDES = {
    # github
    ("github", "merge_pull_request"): (DENY, "no-merge", "Merging pull requests is a human decision. Leave the PR ready and say so."),
    ("github", "enable_pr_auto_merge"): (DENY, "no-merge", "Auto-merge is a merge with extra steps."),
    ("github", "disable_pr_auto_merge"): (ALLOW, "", ""),
    ("github", "create_repository"): (DENY, "outward", "Creating repositories is out of scope for the agent."),
    ("github", "fork_repository"): (ASK, "outward", "Forking creates a public artefact under the user's account."),
    ("github", "delete_file"): (ASK, "github-write", "Deleting a file through a commit. Recoverable from history, but confirm."),
    ("github", "create_branch"): (ALLOW, "", ""),
    ("github", "create_or_update_file"): (ALLOW, "", ""),
    ("github", "push_files"): (ALLOW, "", ""),
    ("github", "update_pull_request_branch"): (ALLOW, "", ""),
    ("github", "resolve_review_thread"): (ALLOW, "", ""),
    ("github", "unresolve_review_thread"): (ALLOW, "", ""),
    ("github", "run_secret_scanning"): (ALLOW, "", ""),
    ("github", "request_copilot_review"): (ASK, "outward", "Requesting a review notifies people."),
    ("github", "actions_run_trigger"): (ASK, "deploy", "Workflow runs can deploy. Confirm which one."),
    ("github", "issue_write"): (ASK, "outward", "Creating or changing issues notifies people."),
    ("github", "sub_issue_write"): (ASK, "outward", "Changing issues notifies people."),
    ("github", "update_pull_request"): (ASK, "github-write", "Changing the pull request."),
    ("github", "create_pull_request"): (ALLOW, "", ""),
    ("github", "add_comment_to_pending_review"): (ALLOW, "", ""),
    # gmail / mail
    ("Gmail", "delete_draft"): (DENY, "delete", "Deleting a draft is not reversible."),
    ("Gmail", "delete_label"): (DENY, "delete", "Deleting a label is not reversible."),
    ("Gmail", "trash_message"): (ASK, "delete", "Trashing mail. Reversible for 30 days."),
    ("Gmail", "trash_thread"): (ASK, "delete", "Trashing mail. Reversible for 30 days."),
    ("Gmail", "mark_message_spam"): (ASK, "write", "Marking spam."),
    ("Gmail", "mark_thread_spam"): (ASK, "write", "Marking spam."),
    ("Gmail", "create_draft"): (ALLOW, "", ""),
    ("Gmail", "update_draft"): (ALLOW, "", ""),
    ("multi-gmail", "create_draft"): (ALLOW, "", ""),
    # calendar
    ("Google_Calendar", "delete_event"): (DENY, "delete", "Deleting calendar events is not reversible through the API. Decline or update it instead."),
    # drive / sheets
    ("Google_Drive", "trash_file"): (ASK, "delete", "Trashing a Drive file. Reversible for 30 days."),
    ("Google_Drive", "share_file"): (ASK, "outward", "Sharing changes who can see the file."),
    ("Google_Sheets", "batch_clear_values"): (DENY, "delete", "Clearing ranges wipes data. Version history exists, but the agent cannot restore it."),
    ("Google_Sheets", "update_values"): (ASK, "write", "Overwriting cells."),
    ("Google_Sheets", "update_formulas"): (ASK, "write", "Overwriting formulas."),
    ("Google_Sheets", "update_spreadsheet"): (ASK, "write", "Changing the spreadsheet."),
    ("Google_Sheets", "append_values"): (ASK, "write", "Appending rows."),
    ("Google_Sheets", "insert_dimension"): (ASK, "write", "Inserting rows or columns."),
    # claude-code-remote
    ("claude-code-remote", "delete_trigger"): (DENY, "delete", "Deleting a scheduled task also deletes every session it started. Disable it instead."),
    ("claude-code-remote", "archive_session"): (ASK, "write", "Archiving a session."),
    ("claude-code-remote", "create_trigger"): (ASK, "persistence", "Creating a scheduled task that runs on its own later."),
    ("claude-code-remote", "send_later"): (ASK, "persistence", "Scheduling a future message."),
    ("claude-code-remote", "fire_trigger"): (ASK, "persistence", "Firing a scheduled task now."),
    ("claude-code-remote", "update_trigger"): (ASK, "persistence", "Changing a scheduled task."),
    ("claude-code-remote", "create_session"): (ASK, "spawn", "Starting another session."),
    ("claude-code-remote", "send_message"): (ASK, "spawn", "Messaging another session."),
    ("claude-code-remote", "update_environment"): (ASK, "self-config", "Changing the environment's network, variables or setup script."),
    ("claude-code-remote", "create_environment"): (ASK, "self-config", "Creating an environment."),
    ("claude-code-remote", "switch_environment"): (ASK, "self-config", "Switching environment."),
    ("claude-code-remote", "request_credential"): (ALLOW, "", ""),
    ("claude-code-remote", "watch_url"): (ALLOW, "", ""),
    ("claude-code-remote", "unwatch_url"): (ALLOW, "", ""),
    ("claude-code-remote", "subscribe_pr_activity"): (ALLOW, "", ""),
    ("claude-code-remote", "unsubscribe_pr_activity"): (ALLOW, "", ""),
    ("claude-code-remote", "report_preview_port"): (ALLOW, "", ""),
    ("claude-code-remote", "set_session_title"): (ALLOW, "", ""),
    ("claude-code-remote", "set_session_tags"): (ALLOW, "", ""),
    ("claude-code-remote", "register_repo_root"): (ALLOW, "", ""),
    ("claude-code-remote", "add_repo"): (ASK, "scope", "Attaching another repository widens what the session can reach."),
    ("claude-code-remote", "confirm_repository_trust"): (ALLOW, "", ""),
    # docs / artifacts
    ("Claude_Docs", "delete"): (DENY, "delete", "Deleting a document is not reversible."),
    # higgsfield
    ("Higgsfield", "cancel_trial_auto_renewal"): (ASK, "billing", "Billing change."),
    ("Higgsfield", "website_secrets"): (DENY, "secret-read", "Site secrets are not readable or settable through the agent."),
    ("Higgsfield", "website_repo_access"): (ASK, "scope", "Repository access change."),
    ("Higgsfield", "deploy_website"): (ASK, "deploy", "Deploying a site."),
    ("Higgsfield", "publish_website"): (ASK, "outward", "Publishing a site."),
    # meta ads: real money
    ("meta_ads", "ads_activate_entity"): (ASK, "spend", "Activating an ad entity starts spend."),
    ("meta_ads", "ads_update_entity"): (ASK, "spend", "Budget, bid or status change on a live ad account."),
    ("meta_ads", "ads_create_campaign"): (ASK, "spend", "New campaign on a live ad account."),
    ("meta_ads", "ads_create_ad_set"): (ASK, "spend", "New ad set on a live ad account."),
    ("meta_ads", "ads_create_ad"): (ASK, "spend", "New ad on a live ad account."),
    ("meta_ads", "ads_boost_ig_post"): (ASK, "spend", "Boosting a post spends money."),
    ("meta_ads", "ads_update_custom_audience_users"): (ASK, "write", "Changing audience membership."),
    # treg: paid calls
    ("treg", "call"): (ASK, "spend", "Paid API call."),
    ("treg", "call_media"): (ASK, "spend", "Paid media generation."),
    ("treg", "catalog_request"): (ASK, "outward", "Requests a tool from the registry."),
    # canva
    ("Canva", "comment-on-design"): (ASK, "outward", "Comments notify collaborators."),
    ("Canva", "reply-to-comment"): (ASK, "outward", "Comments notify collaborators."),
    ("Canva", "publish-brand-template"): (ASK, "outward", "Publishing to the brand."),
    # constant contact: real customer mail
    ("Constant_Contact", "create_social_post"): (ASK, "outward", "Social post."),
    ("Constant_Contact", "update_social_post"): (ASK, "outward", "Social post."),
    ("Constant_Contact", "bulk_import_contacts_json"): (ASK, "write", "Bulk contact import into the live list."),
}

SPEND_SERVERS = {
    "Higgsfield": re.compile(r"^(generate|upscale|execute|create_video|create_voice|dubbing|motion|reframe|outpaint|remove_background|animation|ads_studio_generate|build_|ai_influencer_generate|voice_change|scene_builder_3d_generate|video_analysis_create|virality|participate)"),
    "Canva": re.compile(r"^(generate-|create-video|remove-background|separate-image-layers|import-)"),
}


def split_mcp(tool_name):
    rest = tool_name[len("mcp__"):]
    if "__" in rest:
        server, name = rest.split("__", 1)
    else:
        server, name = rest, ""
    return server, name


def check_mcp(tool_name, inp, ctx):
    cfg = ctx.cfg
    out = []
    server, name = split_mcp(tool_name)
    lname = name.lower()
    words = set(re.split(r"[_\-]+", lname))
    key = (server, name)

    # Secret-shaped reads
    singular = {w.rstrip("s") for w in words}
    if (singular & {"secret", "credential", "token", "password"}) and key not in MCP_OVERRIDES:
        if words & MCP_READ_WORDS or words & {"pull", "export"}:
            out.append(Decision(DENY, "secret-read", "This tool returns credentials. The guard keeps them out of the transcript."))
            return out

    if key in MCP_OVERRIDES:
        dec, rule, reason = MCP_OVERRIDES[key]
        d = Decision(dec, rule, reason)
    else:
        d = classify_mcp_generic(server, name, words, cfg)

    # Branch awareness for github writes
    if server == "github" and name in ("create_or_update_file", "push_files", "delete_file", "create_branch", "update_pull_request", "merge_pull_request"):
        branch = inp.get("branch") or inp.get("base") or ""
        if name in ("create_or_update_file", "push_files", "delete_file") and cfg.is_protected_branch(branch):
            d = Decision(DENY, "protected-branch", "Committing straight to %s bypasses review. Use a branch and a pull request." % branch)
    if server == "github" and name == "pull_request_review_write":
        ev = str(inp.get("event") or inp.get("reviewEvent") or "").upper()
        method = str(inp.get("method") or "").lower()
        if ev == "APPROVE":
            d = Decision(DENY, "no-approve", "Approvals count toward merge. The agent does not approve pull requests.")
        elif method in ("submit_pending", "create_and_submit", "submit") or ev:
            d = Decision(ASK, "outward", "Submitting a review notifies people.")
        else:
            d = allow()
    if server == "github" and name in ("add_issue_comment", "add_reply_to_pull_request_comment", "update_issue_comment"):
        d = Decision(ASK, "outward", "Posting on GitHub notifies people.")
    if server == "github" and name == "update_pull_request" and str(inp.get("state") or "").lower() == "closed":
        d = Decision(ASK, "github-write", "Closing the pull request.")

    # Spend servers
    if server in SPEND_SERVERS and SPEND_SERVERS[server].match(lname) and key not in MCP_OVERRIDES and d.decision != DENY:
        d = Decision(ASK, "spend", "This call costs credits.")

    # Budget cap
    if cfg.max_budget is not None:
        for k, v in iter_numeric(inp):
            if re.search(r"budget|bid_amount|spend_cap|daily_spend", k, re.IGNORECASE) and v > cfg.max_budget:
                d = Decision(DENY, "spend-cap", "%s=%s exceeds DRIP_GUARD_MAX_BUDGET_MINOR=%s." % (k, v, cfg.max_budget))

    # Production hints inside the payload
    if d.decision == ASK and d.rule in ("write", "spend", "deploy", "cloud-write"):
        for s in iter_strings(inp):
            if len(s) < 200 and cfg.is_prod(s):
                d = Decision(DENY, "prod-write", "%s (the payload names a production target: %r)" % (d.reason, s[:60]))
                break

    # Secret paths in payloads (e.g. github create_or_update_file path=.env)
    for k in ("path", "file_path", "filename", "name"):
        v = inp.get(k)
        if isinstance(v, str) and classify_secret_path(v, ctx) == DENY and d.decision != DENY:
            d = Decision(DENY, "secret-file", "%s is a secrets file. It is not copied anywhere." % v)
    out.append(d)
    return out


def iter_numeric(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                yield (k, v)
            elif isinstance(v, str) and v.isdigit():
                yield (k, int(v))
            else:
                for x in iter_numeric(v, k):
                    yield x
    elif isinstance(obj, list):
        for v in obj:
            for x in iter_numeric(v, prefix):
                yield x


def classify_mcp_generic(server, name, words, cfg):
    if words & MCP_DELETE_WORDS:
        if words & {"trash"}:
            return Decision(ASK, "delete", "Moving to trash. Reversible, but confirm.")
        return Decision(DENY, "delete", "`%s` on %s deletes something with no undo. Archive, disable or trash it instead, or ask a human." % (name, server))
    if words & MCP_READ_WORDS and not (words & MCP_WRITE_WORDS):
        return allow()
    if words & MCP_REVERSIBLE_WORDS:
        return Decision(ASK, "write", "`%s` on %s changes state (reversibly)." % (name, server))
    if words & MCP_OUTWARD_WORDS:
        return Decision(ASK, "outward", "`%s` on %s reaches other people." % (name, server))
    if words & MCP_WRITE_WORDS:
        if server in cfg.mcp_allow_servers or cfg.mcp_writes == ALLOW:
            return allow()
        if cfg.mcp_writes == DENY:
            return Decision(DENY, "write", "`%s` on %s is a write. Writes are off (DRIP_GUARD_MCP_WRITES=deny)." % (name, server))
        return Decision(ASK, "write", "`%s` on %s writes to a live system." % (name, server))
    if words & MCP_READ_WORDS or not name:
        return allow()
    if server in cfg.mcp_allow_servers or cfg.mcp_writes == ALLOW:
        return allow()
    return Decision(ASK, "unknown", "`%s` on %s is not a known read. Confirm it." % (name, server))


# --------------------------------------------------------------------------
# Other built-in tools
# --------------------------------------------------------------------------

def check_builtin(tool, inp, ctx):
    out = []
    action = str(inp.get("action") or "").lower()
    if tool == "Artifact" and action == "delete":
        out.append(Decision(DENY, "delete", "Deleting a published artifact breaks its link for everyone. Unpublish by replacing content instead."))
    if tool == "ArtifactData" and action in ("delete",):
        out.append(Decision(ASK, "delete", "Deleting shared artifact data."))
    if tool == "ArtifactData" and action in ("batch",):
        out.append(Decision(ASK, "write", "Batch write to shared artifact data."))
    if tool in ("CronCreate",):
        out.append(Decision(ASK, "persistence", "Creating a recurring job."))
    if tool in ("CronDelete",):
        out.append(Decision(ASK, "delete", "Deleting a recurring job."))
    if tool == "Workflow":
        out.append(Decision(ASK, "spawn", "Running a multi-agent workflow spends a lot of tokens."))
    if tool == "WebFetch":
        url = str(inp.get("url") or "")
        if re.search(r"(?:pastebin|transfer\.sh|file\.io|0x0\.st|ngrok|requestbin|webhook\.site|pipedream|hookbin)", url, re.IGNORECASE):
            out.append(Decision(ASK, "exfil", "Fetching from a paste or request-capture service."))
    if tool in ("mcp__Gmail__send_message",):
        pass
    return out


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def evaluate(tool_name, tool_input, ctx):
    cfg = ctx.cfg
    inp = tool_input if isinstance(tool_input, dict) else {}
    decisions = []

    # Secret-shaped strings in anything the agent is about to emit.
    if cfg.secret_scan:
        skip = ("old_string", "pattern") if tool_name in ("Edit", "MultiEdit", "Grep") else ()
        for s in iter_strings(inp, skip_keys=skip):
            hit = scan_secret_tokens(s)
            if hit:
                dec, label = hit
                decisions.append(Decision(dec, "secret-token", "The input contains what looks like a %s. Secrets are never written, sent or echoed; reference them by name only." % label))
                break

    if tool_name == "Bash":
        decisions.extend(check_bash(str(inp.get("command") or ""), ctx))
    elif tool_name in ("Read", "Glob", "Grep", "NotebookRead"):
        decisions.extend(check_read_tool(tool_name, inp, ctx))
    elif tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        decisions.extend(check_write_tool(tool_name, inp, ctx))
        if tool_name == "MultiEdit":
            for e in inp.get("edits") or []:
                if isinstance(e, dict):
                    decisions.extend(check_write_tool("Edit", dict(e, file_path=inp.get("file_path")), ctx))
    elif tool_name.startswith("mcp__"):
        decisions.extend(check_mcp(tool_name, inp, ctx))
    else:
        decisions.extend(check_builtin(tool_name, inp, ctx))

    d = worst(decisions)
    if d.decision == ASK and cfg.mode == "strict":
        d = Decision(DENY, d.rule, d.reason + " (strict mode)")
    return d


def audit(ctx, tool_name, tool_input, d):
    cfg = ctx.cfg
    if d.decision == ALLOW and not cfg.audit_all:
        return
    try:
        path = os.path.expanduser(cfg.audit_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        summary = ""
        if isinstance(tool_input, dict):
            summary = tool_input.get("command") or tool_input.get("file_path") or tool_input.get("url") or json.dumps(tool_input, default=str)
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "session": ctx.session_id,
            "mode": ctx.permission_mode,
            "cwd": ctx.cwd,
            "tool": tool_name,
            "decision": d.decision,
            "rule": d.rule,
            "reason": d.reason,
            "input": redact(str(summary))[:500],
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def emit(d, tool_name, cfg):
    if d.decision == ALLOW:
        return
    reason = "[drip-guardrails:%s] %s" % (d.rule, d.reason)
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": d.decision,
            "permissionDecisionReason": reason,
        }
    }
    if d.decision == DENY:
        payload["systemMessage"] = "drip-guardrails blocked %s: %s" % (tool_name, d.reason)
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


def main():
    cfg = None
    tool_name = "?"
    try:
        cfg = Config()
        if not cfg.enabled:
            return 0
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        tool_name = str(payload.get("tool_name") or "?")
        tool_input = payload.get("tool_input") or {}
        ctx = Context(
            cwd=payload.get("cwd") or os.getcwd(),
            cfg=cfg,
            session_id=str(payload.get("session_id") or ""),
            permission_mode=str(payload.get("permission_mode") or ""),
        )
        d = evaluate(tool_name, tool_input, ctx)
        audit(ctx, tool_name, tool_input, d)
        if cfg.mode == "audit":
            return 0
        emit(d, tool_name, cfg)
        return 0
    except Exception as e:  # never fail open silently
        fail = (cfg.fail if cfg else ASK)
        if fail == ALLOW:
            return 0
        d = Decision(DENY if fail == DENY else ASK, "guard-error", "The guard hit an internal error (%s: %s). Confirm this call by hand." % (type(e).__name__, str(e)[:120]))
        try:
            emit(d, tool_name, cfg)
        except Exception:
            sys.stderr.write("drip-guardrails: internal error, blocking.\n")
            return 2
        return 0


if __name__ == "__main__":
    sys.exit(main())
