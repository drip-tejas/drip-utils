# drip-utils

Small Claude Code plugins, installed from one marketplace. Each plugin works on
its own, so install only the ones you want.

```bash
claude plugin marketplace add drip-tejas/drip-utils
claude plugin install drip-timestamps@drip-utils
claude plugin install drip-session-title@drip-utils
```

Restart Claude Code after installing. Plugins load at session start.

| Plugin | What it does | Needs |
|---|---|---|
| [drip-timestamps](plugins/drip-timestamps) | Local-time stamps on your prompts and Claude's replies, and tells the model when each prompt was sent | nothing for prompt stamps, `python3` for reply stamps |
| [drip-session-title](plugins/drip-session-title) | Names each session after what your first prompt is about, using a short Haiku call | `python3`, a logged-in Claude Code |

## Tests

```bash
bash plugins/drip-timestamps/test/run-tests.sh
python3 plugins/drip-session-title/test/test_session_title.py
```

## License

MIT. See [LICENSE](LICENSE).
