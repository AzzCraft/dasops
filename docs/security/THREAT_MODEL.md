# dasops v1.0 Threat Model

The public release covers the local Python CLI and its generated template.
Primary risks are malicious or malformed repository input, concurrent task
claims, and accidental disclosure through committed artifacts. Mitigations are
path validation, fail-closed verification, exclusive task-lock creation,
atomic file replacement, and source-boundary scans.

Network services, control planes, plugins, customer support systems, update
channels, and remote key management are outside this release's scope.
