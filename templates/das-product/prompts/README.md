# Prompt templates

These prompt templates are the default starting point for:

- Orchestrator work in the Codex IDE extension
- Worker runs in Codex CLI non-interactive mode

Files in this folder are part of the product repo generation contract. Keep them stable and versioned.

Recommended usage:

- Orchestrator: copy `prompts/orchestrator.md` into the IDE agent chat as the first message.
- Worker: pipe `dasops prompt --role worker --change-id <id> --task-id T-001` into `codex exec`.
