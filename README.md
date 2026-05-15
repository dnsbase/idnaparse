# idnaparse

An IDNA-aware DNS-name lint and reporter.  Reads
presentation-form domain names from stdin (one per line) and
emits one JSON record per name on stdout.

Useful for sweeping a zone file or registrar feed for IDNA
conformance, summarising the label kinds present in a corpus, or
as a parsing front end for ad-hoc DNS-name analysis pipelines.

Built on the [`idna2008`](https://github.com/dnsbase/idna2008)
library; was previously bundled with `dnsbase` and is now a
standalone project so it can be used without pulling in the
broader DNS-message machinery.

## Quick start

```sh
$ cabal install idnaparse

$ printf '%s\n' 'www.example.com' 'müllers.example.de' '_25._tcp.example' |
  idnaparse --summary | jq
{
  "input": {
    "text": "www.example.com",
    "forms": [
      "LDH",
      "LDH",
      "LDH"
    ]
  },
  "presentation": "www.example.com",
  "output": {
    "text": "www.example.com",
    "forms": [
      "LDH",
      "LDH",
      "LDH"
    ]
  }
}
{
  "input": {
    "text": "müllers.example.de",
    "forms": [
      "ULABEL",
      "LDH",
      "LDH"
    ]
  },
  "presentation": "xn--mllers-kva.example.de",
  "output": {
    "text": "müllers.example.de",
    "forms": [
      "ULABEL",
      "LDH",
      "LDH"
    ]
  }
}
{
  "input": {
    "text": "_25._tcp.example",
    "forms": [
      "ATTRLEAF",
      "ATTRLEAF",
      "LDH"
    ]
  },
  "presentation": "_25._tcp.example",
  "output": {
    "text": "_25._tcp.example",
    "forms": [
      "ATTRLEAF",
      "ATTRLEAF",
      "LDH"
    ]
  }
}
{
  "summary": {
    "ok": 3,
    "fail": 0,
    "discard": {
      "overlong": 0,
      "badutf8": 0
    },
    "forms": {
      "ATTRLEAF": 1,
      "LDH": 3,
      "ULABEL": 1
    },
    "reasons": {}
  }
}
```

## Output schema

### Success rows

```json
{ "input"        : { "text": "...", "forms": ["...", ...] },
  "presentation" : "...",                  // canonical RFC 1035 form
  "output"       : { "text": "...", "forms": ["...", ...] },
  "fakes"        : [{...}]                 // present iff a FAKEA label appeared
}
```

`input.forms` is the parser's per-label classification; `output.forms`
is the unparser's.  With validation enabled (the default), an `ALABEL`
in `output.forms` signals BIDI-driven ASCII fallback: the label would
have decoded to Unicode if the cross-label rules had allowed it.

When input mappings are enabled (e.g. `--opts +map-width`), the
parser's classification reflects the *post-mapping* label, not the
raw input bytes.  A label written in fullwidth Latin letters
(`０-９Ａ-Ｚａ-ｚ`) maps to plain ASCII and classifies as `LDH`,
even though the input bytes were non-ASCII.  This is by design:
the mappings exist to correct input-method artefacts that produce
non-ASCII representations of what the user meant to type as ASCII.
It does mean `input.forms` may not be a faithful record of "did the
input have non-ASCII bytes" when mappings are active; if you need
that distinction, inspect `input.text` directly (or don't enable
"width" mappings).

### Failure rows

Two shapes, depending on where the failure happens:

```json
// Parse failure -- the input text did not parse.
{ "input": { "text": "...",
             "error": { "reason": "...", ... } } }

// Unparse failure -- the input parsed but the wire form could not be
// rendered under the given options (e.g. cross-label Bidi without
// ascii-fallback, or an admitted form set whose output classification
// is not also admitted).
{ "input"        : { "text": "...", "forms": ["...", ...] },
  "presentation" : "...",
  "output"       : { "error": { "reason": "...", ... } },
  "fakes"        : [{...}] }                  // present iff a FAKEA label appeared
```

The `error` object carries the standard set of optional fields
(`label`, `cp`, `length`, `form`, `rule`).

Overlong input lines and ill-formed UTF-8 produce no row; they are
counted in the optional summary.

## Configuration

`--forms FORMS`  permitted label-form tokens (e.g. `host`,
`+attrleaf`, `idn,wildlabel`).  See `--explain-forms` for the
full vocabulary.

`--opts OPTS`  IDNA option tokens (e.g. `default`, `+emoji-ok`,
`map,bidi-check`).  See `--explain-opts` for the full vocabulary.

`--summary`  emit a trailing summary record with per-class and
per-error counters.

`--no-rows`  suppress per-row records (combine with `--summary`
when only aggregate output is wanted).

## Status

Initial release (`1.0.0.0`).

## License

BSD-3-Clause.
