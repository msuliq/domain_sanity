# frozen_string_literal: true

require_relative "domain_sanity/version"
require_relative "domain_sanity/policy"
require_relative "domain_sanity/reason"
require_relative "domain_sanity/idn"
require_relative "domain_sanity/ip"
require_relative "domain_sanity/name"
require_relative "domain_sanity/subject"
require_relative "domain_sanity/data"

# DomainSanity validates and inspects domain names the strict way a
# certificate authority must: RFC 1035 label rules, IDN/punycode handling,
# Public Suffix List and TLD checks, CA/Browser Forum aware wildcard rules,
# and IP / reserved-range / reverse-zone detection.
#
# Scope: this is offline, structural validation only. It does NOT resolve DNS,
# check CAA records, verify that a name exists, or enforce certificate field
# lengths (e.g. CN <= 64). IDN conversion is IDNA2003-style punycode via
# SimpleIDN, not full UTS-46 (see DomainSanity::IDN). Those remain the caller's
# responsibility.
#
# What "valid" means is governed by a Policy; pass `policy:` a preset symbol
# (:ca_baseline, :dns_zone, :lenient), a Hash of overrides, or a Policy. The
# module-level methods are the friendly front door. For several questions about
# one subject, build a typed Subject once with .analyze and reuse it.
module DomainSanity
  module_function

  # Structurally valid FQDN with a real public TLD under the given policy.
  # Wildcards, IP literals, and reverse-zone names are excluded here.
  def valid?(subject, policy: :ca_baseline)
    Name.valid?(subject, policy: policy)
  end

  # Structured reasons subject is not a valid FQDN, as Reason objects (code,
  # message, label). Empty array means valid.
  def reasons(subject, policy: :ca_baseline)
    Name.reasons(subject, policy: policy)
  end

  def wildcard?(subject)
    Name.wildcard?(subject)
  end

  # Baseline-Requirements-valid wildcard: "*" is the whole leftmost label and
  # the remainder is not a bare public suffix.
  def valid_wildcard?(subject, policy: :ca_baseline)
    Name.valid_wildcard?(subject, policy: policy)
  end

  # True when subject is itself a recognized public suffix (eTLD), e.g. "com"
  # or "co.uk". A full name like "example.com" is not a suffix and returns
  # false.
  def valid_tld?(subject, policy: :ca_baseline)
    Name.valid_tld?(subject, policy: policy)
  end

  def registrable_domain(subject, policy: :ca_baseline)
    Name.registrable_domain(subject, policy: policy)
  end

  def public_suffix(subject, policy: :ca_baseline)
    Name.public_suffix(subject, policy: policy)
  end

  def ip?(subject)
    IP.ip?(subject)
  end

  # Private or otherwise reserved (non-public) IP. The BRs forbid issuing for
  # these.
  def reserved_ip?(subject)
    IP.reserved?(subject)
  end

  def public_ip?(subject)
    IP.public?(subject)
  end

  def reverse_zone?(subject)
    IP.reverse_zone?(subject)
  end

  def to_ascii(subject)
    IDN.to_ascii(subject)
  end

  def to_unicode(subject)
    IDN.to_unicode(subject)
  end

  # True when any label mixes scripts in a homograph-suspicious way (Latin with
  # Cyrillic, etc.). Opt in to enforcing this during validation with a policy of
  # { require_single_script: true }.
  def mixed_script?(subject)
    IDN.mixed_script?(subject)
  end

  # A typed, lazily-memoized Subject (Hostname / Wildcard / IPSubject /
  # ReverseZone / MalformedSubject) exposing every fact about subject. Named
  # .analyze (not .inspect) so it does not shadow Object#inspect.
  def analyze(subject, policy: :ca_baseline)
    Subject.for(subject, policy: policy)
  end

  # Provenance and staleness of the reference data (reserved-IP snapshot, PSL
  # and IDNA gem versions).
  def data_versions
    Data.versions
  end
end
