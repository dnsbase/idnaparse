# Changelog

## 0.1.0.0

Initial release as a standalone project, factored out of the
`dnsbase` library and rebased on the `idna2008` library.

- `idnaparse` CLI: reads UTF-8 presentation-form names from stdin
  (one per line) and emits one JSON record per name on stdout.
- Success rows report the canonical presentation form, the
  Unicode display form, and the set of label-form classifications
  (LDH, ALABEL, ULABEL, FAKEA, ATTRLEAF, OCTET, WILDLABEL).
- Failure rows report a structured error with the offending label
  index, the rule or codepoint that failed, and (for Bidi
  violations) the specific RFC 5893 rule.
- `--forms` selects the permitted label-form classes;
  `--opts` selects the IDNA validation flags, input mappings, and
  presentation policy.  Both accept comma-separated tokens with
  `+`/`-` prefix arithmetic and the same vocabulary as the
  `idna2008` library's `parseLabelFormSet` and `parseIdnaFlags`.
- `--summary` emits a trailing summary record with per-class and
  per-error counters.
- `--explain-forms` and `--explain-opts` print the full
  vocabulary glossaries.
