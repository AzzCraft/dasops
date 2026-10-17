# Data Boundary and Redaction Policy

DAS separates customer data, operational metadata, evidence, logs, and support material into explicit trust zones. The default rule is local processing: source code, evidence bundles, logs, and diagnostic bundles stay inside the customer-controlled workspace unless an operator exports them.

## Boundary Classes

| Class | Examples | Export rule | Required redaction |
| --- | --- | --- | --- |
| customer-source | repository files, generated patches, policy inputs | never exported by default | path, email, token, private key, license value |
| metadata | repo IDs, task IDs, run IDs, timestamps | export allowed for support | tenant ID and user identifiers |
| evidence | EvidenceBundle, replay logs, audit export | export allowed only by operator action | source snippets, filesystem paths, secrets |
| logs | CLI logs, control-plane logs, plugin logs | support bundle only | tokens, emails, home paths, credential fields |
| support | diagnostics, health reports, license state | explicit support packet | license value, private config, API credentials |

`tools/security/check_redaction.py` validates that exported JSON does not contain the secret-like patterns enforced by `shared/logging/redaction.py`.
