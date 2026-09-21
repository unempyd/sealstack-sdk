# Deviations from the specification

Recorded facts about where this SDK differs from the SealStack specification.

- `sdk/sealstack/` is the package; the specification's repository structure
  names `sdk/product/`. The distribution is `sealstack`, so the import name
  matches it. `sdk/product/` is kept as a compatibility alias of the same
  module objects, because `from product import AuditClient` is the import form
  the specification documents and was what 0.1.2 published. Nothing is
  duplicated: `product.<name>` and `sealstack.<name>` are one module each.

- `sdk/sealstack/__init__.py` is not listed in the specification's repository
  structure. It exists so that the documented import form
  `from sealstack import AuditClient` works; without it the package is a
  namespace package and that import fails.

- `sdk/sealstack/export.py` is an SDK module not listed in the specification's
  repository structure. It holds the external-format exporters behind
  `sealstack export --format {aerf,agent-receipts,scitt}` (AERF v0.1.0-draft.1,
  Agent Receipt Protocol v0.5.0, the noa SCITT profile bare receipt). The
  specification defines the native evidence bundle only; these exports are
  additive, sign with the agent key, never alter the native format, and label
  every field SealStack does not record instead of inventing one.
