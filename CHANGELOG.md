# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Initial release.
- FQDN validation per RFC 1035 label and length rules.
- IDN / punycode round-tripping via SimpleIDN.
- TLD membership checks against the ICANN Public Suffix List.
- CA/Browser Forum aware wildcard validation.
- IP address, private/reserved range, and reverse-zone detection.
- `reasons` returns structured `Reason` objects (stable `code`, human-readable
  `message`, offending `label`) that still render to their message as strings.
- A single trailing "root" dot (`example.com.`) is accepted and normalized.
- `IP.public?` / `DomainSanity.public_ip?` parse the address only once.
- **`Policy`** makes validation choices data instead of boolean flags: presets
  `:ca_baseline` (default), `:dns_zone`, `:lenient`, plus per-field overrides
  (`allow_underscore`, `allow_single_label`, `allow_trailing_dot`,
  `include_private_suffixes`, `allow_reserved_tld`, `require_single_script`).
  Every entry point takes a `policy:` argument (a Symbol, Hash, or `Policy`).
- `allow_reserved_tld` accepts RFC 6761/6762/7686 special-use TLDs (`.test`,
  `.local`, `.onion`, `.internal`, …) that are not in the Public Suffix List;
  `:lenient` enables it, which is what distinguishes it from `:dns_zone`.
- **Typed subjects.** `analyze` classifies the input once and returns a
  `Hostname`, `Wildcard`, `IPSubject`, `ReverseZone`, or `MalformedSubject`.
  Kind-specific methods live only on the type they apply to (an `IPSubject` has
  no `registrable_domain`). Facts are computed lazily and memoized.
- **Homograph guard.** `IDN.mixed_script?` / `DomainSanity.mixed_script?` flag
  labels that combine scripts a Unicode registry would disallow (Latin with
  Cyrillic, etc.), while permitting legitimate combinations (Japanese, Chinese,
  Korean). Enforced during validation via `require_single_script`.
- **Data provenance.** `DomainSanity.data_versions` reports the reserved-IP
  snapshot date and PSL / IDNA gem versions; `rake data:check` fails when the
  vendored IP snapshot is stale; `rake data:sync` documents the refresh steps.

### Design decisions

- `valid?` rejects IP literals and reverse-DNS zone names (`in-addr.arpa` /
  `ip6.arpa`) as well as wildcards; `DomainSanity.valid?` and
  `Subject#valid?` are guaranteed to agree for every input.
- `valid_tld?` answers "is this argument itself a public suffix" (`com`,
  `co.uk` → true; `example.com` → false), rather than validating a whole name.
- Public-suffix treatment is policy-driven: ICANN-only by default, with private
  entries (`github.io`) enabled via `include_private_suffixes`. Whichever is in
  effect is applied consistently to validity, `registrable_domain`,
  `public_suffix`, and wildcard checks.
- The inspection entry point is `DomainSanity.analyze` (was `.inspect`, which
  shadowed `Object#inspect`); it returns a `DomainSanity::Subject` subclass
  (the earlier single `Analysis` / `Result` object is gone).
- `ip?` accepts only single host addresses; prefix / CIDR notation such as
  `10.0.0.0/8` returns false.
- Reserved-range lists extended to match the current IANA special-purpose
  registries (e.g. `192.31.196.0/24`, `3fff::/20`, `5f00::/16`).

### Security

- Input longer than `MAX_INPUT_BYTES` (1024) is rejected up front with an
  `:input_too_long` reason, before any IDN conversion or Public Suffix parsing,
  so an untrusted caller can't force unbounded CPU/memory with a huge string.
- Documented that non-canonical IP encodings (`010.0.0.1`, `0x7f.0.0.1`,
  `2130706433`) are treated as host names, not IPs; callers using
  `reserved_ip?` for SSRF defense should canonicalize first.

### Fixed

- Non-String input (Integer, Symbol, Array, …) is now classified as
  `:not_a_string` and reported invalid, instead of raising `NoMethodError` from
  the validation path.
- `valid_wildcard?` honors `allow_reserved_tld`: under `:lenient`, a wildcard on
  a reserved-TLD name (`*.foo.test`) is permitted, matching `valid?("foo.test")`.
  A bare reserved TLD (`*.test`) is still rejected.
- `IP.parse` skips `IPAddr.new` for strings that can't be an address, avoiding a
  raised-and-rescued exception on the hot path for every non-IP host name.
- `Subject#to_h` exposes a uniform key set across all kinds (nil where a fact
  does not apply), so serialized output has a stable shape; the typed methods
  remain kind-specific.

### Changed

- `Policy.preset` dispatches via a case instead of rebuilding a hash of bound
  methods on every call; `Policy.presets` now returns the preset names.
- The wildcard remainder is normalized once (shared
  `Name.valid_wildcard_remainder?`), and the mixed-script check reuses the
  already-decoded Unicode form.

### Scope

- Offline, structural validation only: no DNS resolution, CAA, existence
  checks, or certificate field-length enforcement. IDN conversion is IDNA2003
  punycode (SimpleIDN), not full UTS-46 / IDNA2008.
