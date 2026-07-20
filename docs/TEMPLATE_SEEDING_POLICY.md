# Template Seeding Policy

`dasops create` copies a standalone DAS/OpenSpec product baseline and then
installs the supplied master document and UI specification.

The template includes `STANDARD_REF.md`, `scripts/verify`, task-lock support,
and standard OpenSpec files. It must not include copied standard text, absolute
host paths, invented extension records, unresolved closure pins, or Cadence/
suite integration hooks that cannot be verified end to end.

Existing repositories are never automatically reseeded. Any later governed
integration requires an owner-reviewed, immutable, schema-valid closure.
