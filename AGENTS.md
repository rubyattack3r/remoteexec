## Session wiki

`.wiki/` is gitignored cross-session memory following the
[llm-wiki pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).
It is never shipped or committed; shipped docs must not link to it. Read relevant
pages before work when it exists. Before handing off, update the owning page
with durable context you discovered or changed; create the directory and index
only when such context exists. Keep current truth and links to source-tree
evidence, not logs, prompts, transcripts or issue discussions.

- `index.md`: one link and one-line summary per page; update on add/rename/remove.
- `log.md`: at most about 20 distilled `## [YYYY-MM-DD]` entries on what changed
  and why; no raw tool output. Prune entries once a topic page holds the facts.
- `environment.md`: test hosts, access patterns and companion checkout paths,
  updated in place. Never record SSH keys, passwords or other secrets.
- `architecture.md`: package/adapter boundaries and business rules, aligned with
  this file. This file stays authoritative on conflict.
- `requirements.md`: approved product scope and milestone approvals.
- `findings.md`: root causes and observability traps as problem → cause → fix;
  delete superseded findings.
- `next-steps.md`: actionable follow-up, blockers and pending verification;
  remove completed items promptly.

## Scratch workspace

`.scratch/` is gitignored disposable workspace for code spikes, downloaded
tools, generated binaries, rendered output, logs and other reproducible test
artifacts. It may be deleted at any time and is never a source of truth. Do not
put `.wiki/` inside it. Promote durable code or fixtures into the tracked source
tree, and distill durable context into the owning `.wiki/` page before handoff.
Repository development scripts may write reproducible output there, but shipped
runtime behavior and documentation must not require or link to `.scratch/`.
Gitignored does not mean secure: do not use `.scratch/` or `.wiki/` as a secret
store.
