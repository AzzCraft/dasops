# Data Boundary and Export Review

DASOps works on the product directory selected by its caller. Scaffolding copies
the supplied Master Doc/UI Spec, templates and change artifacts into that directory.
Local task commands read/write Markdown and YAML. Protected references use their
installed authority and evidence-store boundaries; see
[`protected/candidates/README.md`](../../dasops/protected/candidates/README.md).

No general export redaction or support-upload service is provided here. CLI output,
exceptions, repository files and evidence may contain source snippets, paths,
identifiers or credentials supplied by the operator. Do not export them by default.
Before sharing, select the minimum files, review their contents, and prepare a
separate sanitized copy. Preserve original signed bytes under their original
access controls: changing a display copy does not preserve its signature identity.

| Material | Handling |
|---|---|
| Source and task inputs | Treat as product data; share only with explicit permission |
| Evidence, logs and configuration | Review source snippets, home paths, tokens, URLs and identities |
| Credentials and signed private inputs | Keep out of public source and support packets; rotate on exposure |
| Public synthetic fixtures | Retain their test purpose; they confer no operational authority |

File hashes detect changed bytes; they do not detect or remove sensitive content.
Installed applications remain responsible for their real storage/network permissions.
