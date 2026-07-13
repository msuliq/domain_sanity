# DomainSanity

[![CI](https://github.com/msuliq/domain_sanity/actions/workflows/pull_request.yml/badge.svg)](https://github.com/msuliq/domain_sanity/actions/workflows/pull_request.yml)
[![Gem Version](https://badge.fury.io/rb/domain_sanity.svg)](https://rubygems.org/gems/domain_sanity)

Strict, standards-based domain name validation and inspection for Ruby,
written the way a certificate authority has to think about names.

Most "is this a valid domain" helpers stop at a regex. A CA cannot. It has to
know that a label may not exceed 63 octets, that the whole name may not exceed
253, that `example.123` has an all-numeric TLD, that `*.co.uk` is a forbidden
wildcard while `*.example.com` is fine, that `münchen.de` and its punycode
form `xn--mnchen-3ya.de` are the same name, and that `10.0.0.1` and
`1.2.0.192.in-addr.arpa` are not issuable host names at all.

DomainSanity packages that judgment behind a small, fast API with two lean,
pure-Ruby dependencies.

## Why it exists

- **Standards, not guesswork.** RFC 1035 label and length rules, RFC
  5890/5891 for internationalized names, the ICANN Public Suffix List for TLD
  membership, and CA/Browser Forum Baseline Requirements for wildcards.
- **Small and fast.** Two runtime dependencies (`public_suffix`, `simpleidn`),
  both pure Ruby. `IPAddr` comes from the standard library.
- **Honest answers.** `reasons` tells you *why* a name failed, so you can show
  a useful error instead of a shrug.
- **Policy, not hardcoded rules.** "Valid" means different things to a CA, a
  DNS zone editor, and a lenient form validator. Choose with a `policy:`.

## Scope

DomainSanity is **offline, structural validation only**. It does not resolve
DNS, check CAA records, confirm a name exists, enforce certificate field
lengths (e.g. `CN <= 64`), or perform full UTS-46 / IDNA2008 processing — IDN
conversion is IDNA2003-style punycode via SimpleIDN (see [IDN and homographs](#idn-and-homographs)).
Those remain the caller's responsibility. What it *does* do it does strictly
and fast, with structured, machine-readable answers.

Input longer than 1024 bytes is rejected up front (before any IDN or Public
Suffix work) as a denial-of-service guard — no real domain name approaches that.

**Using this for SSRF defense?** Non-canonical IP encodings (`010.0.0.1`,
`0x7f.0.0.1`, `2130706433`) are *not* recognized as IPs — they're treated as
(invalid) host names, so `reserved_ip?` / `public_ip?` return `false` for them.
That means they can't bypass the reserved-range check *here*, but a downstream
HTTP client or resolver might still interpret them as addresses. Canonicalize
addresses yourself before trusting any allow/deny decision.

## Installation

```ruby
gem "domain_sanity"
```

Then `bundle install`, or `gem install domain_sanity`.

## Usage

```ruby
require "domain_sanity"

DomainSanity.valid?("example.com")            # => true
DomainSanity.valid?("www.example.co.uk")      # => true
DomainSanity.valid?("münchen.de")             # => true (IDN)
DomainSanity.valid?("example.123")            # => false (all-numeric TLD)
DomainSanity.valid?("example.nope")           # => false (unknown TLD)
DomainSanity.valid?("-bad.example.com")       # => false (leading hyphen)

# Tell the user what went wrong. `reasons` returns structured Reason objects
# (code, message, offending label); each renders to its message as a string.
DomainSanity.reasons("-bad.example.123").map(&:message)
# => ["has an invalid label: \"-bad\"", "has an all-numeric TLD",
#     "has a TLD that is not in the Public Suffix List"]
DomainSanity.reasons("-bad.example.123").map(&:code)
# => [:label_invalid, :numeric_tld, :unknown_tld]

# IP literals and reverse zones are not host names, so `valid?` rejects them.
DomainSanity.valid?("192.0.2.10")                    # => false (IP, not a name)
DomainSanity.valid?("1.2.0.192.in-addr.arpa")        # => false (reverse zone)

# `valid_tld?` asks whether the argument is itself a public suffix (eTLD).
DomainSanity.valid_tld?("com")                # => true
DomainSanity.valid_tld?("co.uk")             # => true
DomainSanity.valid_tld?("example.com")        # => false (a name, not a suffix)

# Wildcards, per the Baseline Requirements
DomainSanity.valid_wildcard?("*.example.com") # => true
DomainSanity.valid_wildcard?("*.co.uk")       # => false (bare public suffix)
DomainSanity.valid_wildcard?("ba*.example.com") # => false (embedded)

# IP addresses and reverse zones
DomainSanity.ip?("192.0.2.10")                # => true
DomainSanity.reserved_ip?("10.0.0.1")         # => true  (RFC 1918)
DomainSanity.public_ip?("1.1.1.1")            # => true
DomainSanity.reverse_zone?("1.2.0.192.in-addr.arpa") # => true

# Registrable domain and public suffix
DomainSanity.registrable_domain("a.b.example.co.uk") # => "example.co.uk"
DomainSanity.public_suffix("a.b.example.co.uk")      # => "co.uk"

# IDN round-tripping
DomainSanity.to_ascii("münchen.de")           # => "xn--mnchen-3ya.de"
DomainSanity.to_unicode("xn--mnchen-3ya.de")  # => "münchen.de"
```

### Analyze once, ask many times

When you have several questions about one name, `analyze` classifies it once and
returns a **typed subject** — a `Hostname`, `Wildcard`, `IPSubject`,
`ReverseZone`, or `MalformedSubject`. Facts are computed lazily and memoized, so
one question is cheap and many re-parse nothing:

```ruby
r = DomainSanity.analyze("www.example.co.uk")   # => DomainSanity::Hostname
r.valid?              # => true
r.kind                # => :hostname
r.registrable_domain  # => "example.co.uk"
r.public_suffix       # => "co.uk"
r.to_h                # => { input:, kind:, valid:, registrable_domain:, ... }

ip = DomainSanity.analyze("10.0.0.1")           # => DomainSanity::IPSubject
ip.reserved?          # => true
ip.public?            # => false
ip.registrable_domain # => NoMethodError — an IP has no registrable domain
```

Methods that only make sense for one kind live only on that type, so you can't
ask an IP for its registrable domain. The entry point is `analyze` (not
`inspect`, which would shadow `Object#inspect`). `Subject#valid?` means exactly
what `DomainSanity.valid?` means: a structurally valid plain host name.
Wildcards, IPs, and reverse zones are not "valid" in that sense and expose their
own predicates (`valid_wildcard?`, `public?`).

While the *methods* are kind-specific, `to_h` is uniform: every subject
serializes the same key set, with `nil` where a fact does not apply to that kind,
so downstream `dig`/`present?` checks work the same for any input.

## Policies

What counts as valid is a `Policy`. Pass `policy:` a preset symbol, a Hash of
overrides, or a `Policy` instance; the default is `:ca_baseline`.

```ruby
DomainSanity.valid?("_dmarc.example.com")                          # => false
DomainSanity.valid?("_dmarc.example.com", policy: :dns_zone)       # => true
DomainSanity.valid?("_dmarc.example.com", policy: { allow_underscore: true })
DomainSanity.valid?("intranet-host",       policy: :dns_zone)      # => true (single label)
DomainSanity.public_suffix("foo.github.io", policy: :dns_zone)     # => "github.io"
```

| Field | `:ca_baseline` | Meaning |
| --- | --- | --- |
| `allow_underscore` | `false` | permit `_` in labels (RFC 952/1123 forbid it) |
| `allow_single_label` | `false` | permit a bare host with no TLD (`intranet`) |
| `allow_trailing_dot` | `true` | accept & normalize one trailing root dot |
| `include_private_suffixes` | `false` | treat private PSL entries (`github.io`) as suffixes |
| `allow_reserved_tld` | `false` | accept special-use TLDs (`.test`, `.local`, `.onion`, `.internal`) |
| `require_single_script` | `false` | reject confusable mixed-script IDN labels |

Presets: `:ca_baseline` (strict, the default), `:dns_zone` (underscores,
single-label hosts, and private suffixes allowed), `:lenient` (all of that plus
RFC 6761/6762/7686 special-use TLDs).

`allow_reserved_tld` only affects validity — a reserved TLD is not in the Public
Suffix List, so `registrable_domain` / `public_suffix` stay `nil` for names like
`foo.test`.

## IDN and homographs

IDN conversion (`to_ascii` / `to_unicode`) uses SimpleIDN, which is IDNA2003
punycode — **not** a full UTS-46 / IDNA2008 processor. Mapping of a few code
points (final sigma, ß, ZWJ/ZWNJ) differs from the current standard; normalize
upstream with a UTS-46 library if you need that exactness.

`mixed_script?` is a lightweight homograph guard that flags labels combining
scripts a Unicode registry would not allow (Latin with Cyrillic, etc.), while
permitting legitimate combinations like Japanese (`例え.jp`):

```ruby
DomainSanity.mixed_script?("аpple.com")   # => true  (Cyrillic "а" + Latin)
DomainSanity.mixed_script?("münchen.de")  # => false
DomainSanity.valid?("аpple.com", policy: { require_single_script: true }) # => false
```

## Notes

- **A single trailing dot is accepted** by default (`allow_trailing_dot`).
  `example.com.` denotes the same name as `example.com`; a second trailing dot
  (`example.com..`) is an empty label and is rejected.
- **`valid?` is consistent everywhere.** `DomainSanity.valid?(x)` and
  `analyze(x).valid?` always agree: both mean "a structurally valid plain host
  name," so wildcards, IPs, and reverse zones return `false`.
- **Data provenance.** `DomainSanity.data_versions` reports the reserved-IP
  snapshot date and the PSL / IDNA gem versions; `rake data:check` fails when
  the vendored IP snapshot goes stale.

## What it checks

| Rule | Source |
| --- | --- |
| Label 1-63 octets, name <= 253 octets, <= 127 labels | RFC 1035 |
| Letter-digit-hyphen labels, no leading/trailing hyphen | RFC 952 / 1123 |
| TLD not all-numeric | RFC 3696 |
| TLD present in the ICANN Public Suffix List | Public Suffix List |
| IDN normalized before suffix checks | RFC 5890 / 5891 |
| Wildcard only as the whole leftmost label, never a bare suffix | CA/B Forum BR 3.2.2.6 |
| Private / reserved IP detection | RFC 1918 / 4193 / 6890 |
| Reverse-zone detection | RFC 1035 / 3596 |

## Development

```bash
bundle install
bundle exec rake spec          # run the test suite
bundle exec standardrb         # lint (Standard Ruby)
bundle exec rake data:check    # verify the vendored reserved-IP snapshot is current
```

The reserved-IP ranges are vendored by hand; `rake data:sync` prints the refresh
steps, and `rake data:check` (also run in CI) fails when the snapshot goes stale.

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

Please make sure `bundle exec rake spec` and `bundle exec standardrb` both pass.

## License

Available as open source under the [MIT License](LICENSE).
