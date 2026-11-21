<p align="center">
  <img src="https://raw.githubusercontent.com/Nexqor/Nexqor/main/banner.png" alt="Nexqor" width="100%">
</p>

<h1 align="center">rag-canary 🐤</h1>

<p align="center">
  <b>Canary tokens for RAG pipelines and AI assistants.</b><br/>
  Plant a unique marker in every sensitive document. If it ever shows up in a model answer,<br/>
  a chat log or a paste site, you know <b>exactly which document leaked</b>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-c41237?style=for-the-badge&logo=python&logoColor=white" alt="python"/>
  <img src="https://img.shields.io/badge/dependencies-0-c41237?style=for-the-badge" alt="deps"/>
  <img src="https://img.shields.io/badge/detects-RAG%20leaks-000000?style=for-the-badge" alt="detects"/>
</p>

---

## The problem

RAG systems mix documents with very different sensitivity into one search index. When permissions are wrong, a prompt injection lands, or a model memorizes fine-tuning data, private content leaks **quietly**. Usually nobody notices until it is on a forum.

Canary tokens turn a silent leak into a detectable event.

## How it works

```text
  plant                      index                     detect
┌────────────┐   embed   ┌─────────────┐  leak   ┌──────────────────────┐
│ salaries.md│ ────────▶ │  RAG index  │ ──────▶ │ answer / log / paste │
│ + token    │           │  (vectors)  │         │ contains token       │
└────────────┘           └─────────────┘         └──────────┬───────────┘
                                                            │ scan
                                                  [LEAK] "HR salary bands"
```

1. Each token is unique and carries a short **HMAC tag** tied to your registry secret, so random look-alike strings don't cause false alarms.
2. Tokens are written as natural-looking lines (`Document ID`, `Internal reference key`, contact email, passphrase), which models tend to reproduce verbatim.
3. `scan` searches logs, chat exports and model outputs for exact hits and for **fragments** of a token that was partially rewritten.

## Quick start

```bash
git clone https://github.com/Nexqor/rag-canary && cd rag-canary

# 1. plant canaries in sensitive docs before indexing
python rag_canary.py embed kb/hr/salaries.md --label "HR salary bands 2026" --style key
python rag_canary.py embed kb/legal/*.md --style email

# 2. index kb/ as usual

# 3. watch outputs and logs
python rag_canary.py scan logs/assistant/ exports/chat.json
cat answer.txt | python rag_canary.py scan -
```

Output:

```text
[LEAK] logs/assistant/2026-11-21.jsonl:4182  'HR salary bands 2026'  (exact)
       token sk-canary-3f9a1c07be41d2e9  planted in kb/hr/salaries.md
```

Exit code is `1` on any hit, so it drops straight into cron, CI or a SIEM pipeline.

## Token styles

| Style | Looks like | Best for |
|-------|-----------|----------|
| `id` (default) | `NXQ-CANARY-3F9A1C07BE41D2E9` | Easy to grep anywhere |
| `key` | `sk-canary-3f9a1c07be41d2e9` | Tempts exfiltration payloads that hunt for API keys |
| `email` | `cobalt.3f9a1c07be41d2e9@canary-mail.invalid` | Contact-style lines models like to repeat; `.invalid` never resolves |
| `phrase` | `ember-raven-onyx-07be41d2e9` | Survives paraphrasing better than hex |

## Where to scan

- Assistant / chatbot response logs
- LLM gateway logs (LiteLLM, proxies)
- Exports from shared chat tools
- Paste sites and public repos (via your existing monitoring)
- Fine-tuned model outputs: prompt with the doc's title and check if the token comes back (memorization test)

## What a hit means

| Where you found it | Likely cause | Next step |
|--------------------|--------------|-----------|
| Answer to a user without access | RAG retrieval ignores ACLs | Fix permission-aware retrieval ([playbook 04](https://github.com/Nexqor/ai-attack-playbook/blob/main/04-sensitive-data-leakage.md)) |
| Outbound request / image URL | Prompt-injection exfiltration | Egress allowlist, no auto-loaded images ([playbook 02](https://github.com/Nexqor/ai-attack-playbook/blob/main/02-indirect-prompt-injection.md)) |
| Output of a fine-tuned model | Memorization | Remove the doc from training data, retrain |
| Public internet | Full data breach | Incident response: the label tells you which document and where it was planted |

## Notes

- Keep `canaries.json` private: it holds the HMAC secret and the map from token to document.
- Canaries detect leaks, they don't prevent them. Pair with least privilege and permission-aware retrieval.
- Tokens use the reserved `.invalid` TLD and an `sk-canary-` prefix so they never collide with real services.

---

MIT License · Part of the [Nexqor](https://github.com/Nexqor) AI security toolkit · [@whyNexqor](https://x.com/whyNexqor)
