# frozen_string_literal: true

require "set"
require "public_suffix"
require_relative "idn"
require_relative "ip"
require_relative "reason"
require_relative "policy"

module DomainSanity
  # Fully-qualified domain name validation.
  #
  # The checks implement widely published standards, not any one vendor's
  # code: RFC 1035 label syntax and length limits, RFC 5890/5891 for IDN,
  # the Public Suffix List for TLD membership, and the CA/Browser Forum
  # Baseline Requirements for wildcard issuance. Structural length checks run
  # on the ASCII (punycode) form, since the DNS limits are octet limits on the
  # wire format; TLD membership runs on the Unicode form, which is what the
  # Public Suffix List expects.
  #
  # Every entry point funnels a subject through {normalize} exactly once, which
  # classifies it (hostname / wildcard / ip / reverse_zone / empty) and does
  # all IDN conversion and Public Suffix parsing up front. Downstream checks
  # read the precomputed form instead of re-converting.
  #
  # What counts as invalid is governed by a {Policy}: underscores, single-label
  # names, trailing dots, private Public Suffix List entries, and script
  # mixing are all policy choices rather than hardcoded rules.
  module Name
    MAX_DOMAIN_LENGTH = 253
    MAX_LABEL_LENGTH = 63
    MAX_LABELS = 127

    # Hard cap on the raw input, checked before any IDN conversion or Public
    # Suffix parsing so untrusted callers can't force unbounded work with a huge
    # string. No real name comes close: the ASCII form maxes out at 253 octets,
    # and even a pathological all-multibyte IDN stays well under this in its
    # Unicode form. This is a denial-of-service guard, not the DNS length rule
    # (that is MAX_DOMAIN_LENGTH, enforced on the converted ASCII form).
    MAX_INPUT_BYTES = 1024

    LDH_LABEL = /\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/i
    LDH_UNDERSCORE_LABEL = /\A[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\z/i

    NUMERIC = /\A\d+\z/

    # Special-use TLDs that are not delegated in the Public Suffix List but are
    # legitimate in some contexts. Accepted only when a policy sets
    # allow_reserved_tld (:lenient does). Sources: RFC 6761 (example, invalid,
    # localhost, test), RFC 6762 (local), RFC 7686 (onion), and ICANN's
    # private-use ".internal".
    RESERVED_TLDS = Set[
      "example", "invalid", "localhost", "test", "local", "onion", "internal"
    ].freeze

    # The one-pass normalized view of a subject. `kind` is always set; the
    # remaining fields are populated only for the :hostname kind (the other
    # kinds fail fast with a single reason and need no structural analysis).
    #   input   - the original string (or nil)
    #   name    - input with a single trailing "root" dot removed
    #   ascii   - punycode form of name, or nil if unconvertible
    #   unicode - Unicode form of name (falls back to name)
    #   labels  - ascii split on ".", preserving empty edge labels
    #   psl     - PublicSuffix::Domain, or nil if not registrable
    Normalized = Struct.new(
      :input, :name, :ascii, :unicode, :labels, :kind, :psl,
      keyword_init: true
    )

    module_function

    # Classify and pre-parse a subject exactly once. Cheap for the non-hostname
    # kinds, which return early before any IDN/PSL work. `policy` only affects
    # whether private Public Suffix List entries count as suffixes.
    def normalize(subject, policy = Policy.ca_baseline)
      return Normalized.new(input: subject, kind: :nil) if subject.nil?
      return Normalized.new(input: subject, kind: :not_a_string) unless subject.is_a?(String)
      return Normalized.new(input: subject, kind: :oversized) if subject.bytesize > MAX_INPUT_BYTES
      return Normalized.new(input: subject, kind: :empty) if subject.empty?
      return Normalized.new(input: subject, kind: :whitespace) if subject.match?(/\s/)

      kind = classify(subject)
      return Normalized.new(input: subject, kind: kind) unless kind == :hostname

      name = subject.chomp(".") # a single trailing dot denotes the same FQDN
      ascii = IDN.to_ascii(name)
      unicode = IDN.to_unicode(name) || name
      Normalized.new(
        input: subject,
        name: name,
        ascii: ascii,
        unicode: unicode,
        labels: ascii ? ascii.split(".", -1) : [],
        kind: :hostname,
        psl: parse_psl(unicode, policy)
      )
    end

    # True when subject is a structurally valid FQDN under the given policy.
    # Wildcards, IP literals, and reverse-zone names are never valid here.
    def valid?(subject, policy: :ca_baseline)
      reasons(subject, policy: policy).empty?
    end

    # Structured reasons the subject is not a valid FQDN, as Reason objects.
    # An empty array means valid. This is the single source of truth.
    def reasons(subject, policy: :ca_baseline)
      pol = Policy.coerce(policy)
      reasons_for(normalize(subject, pol), policy: pol)
    end

    # Reasons for an already-normalized subject, so callers that hold a
    # Normalized (such as a Subject) don't re-parse.
    def reasons_for(norm, policy: :ca_baseline)
      pol = Policy.coerce(policy)
      case norm.kind
      when :nil then [reason(:nil, "is nil")]
      when :not_a_string then [reason(:not_a_string, "is not a string")]
      when :oversized then [reason(:input_too_long, "exceeds the maximum input length of #{MAX_INPUT_BYTES} bytes")]
      when :empty then [reason(:empty, "is empty")]
      when :whitespace then [reason(:whitespace, "contains whitespace")]
      when :wildcard then [reason(:wildcard, "is a wildcard (use valid_wildcard?)")]
      when :ip then [reason(:ip_address, "is an IP address, not a host name")]
      when :reverse_zone then [reason(:reverse_zone, "is a reverse-DNS zone name, not a host name")]
      else hostname_reasons(norm, pol)
      end
    end

    # True when subject is itself a recognized public suffix (eTLD), including
    # multi-label suffixes like "co.uk". A full registrable name such as
    # "example.com" is NOT a public suffix and returns false. ICANN suffixes
    # only, unless a policy including private suffixes is passed.
    def valid_tld?(subject, policy: :ca_baseline)
      return false unless subject.is_a?(String)
      return false if subject.empty?

      pol = Policy.coerce(policy)
      unicode = IDN.to_unicode(subject) || subject
      PublicSuffix.parse(unicode, default_rule: nil, ignore_private: !pol.include_private_suffixes)
      false # parsed as a registrable domain, so it is not a bare suffix
    rescue PublicSuffix::DomainNotAllowed
      true # only a bare public suffix parses to "not allowed"
    rescue PublicSuffix::Error
      false
    end

    # True when subject is a wildcard name of the form "*.something".
    def wildcard?(subject)
      subject.is_a?(String) && subject.start_with?("*.")
    end

    # True when subject is a wildcard the Baseline Requirements permit:
    # the "*" is the entire leftmost label, appears exactly once, and the
    # remainder is a valid domain that is NOT itself a bare public suffix.
    def valid_wildcard?(subject, policy: :ca_baseline)
      return false unless wildcard?(subject)
      return false if subject.count("*") != 1

      pol = Policy.coerce(policy)
      valid_wildcard_remainder?(normalize(subject[2..], pol), policy: pol)
    end

    # Whether an already-normalized wildcard remainder is eligible to carry a
    # "*." label: it must validate, and it must have something to the left of
    # its public suffix. For PSL names that means an sld (registrable != tld);
    # for policy-permitted names with no PSL entry (a reserved TLD under
    # allow_reserved_tld) it means at least two labels. Shared so Subject and
    # valid_wildcard? normalize the remainder only once.
    def valid_wildcard_remainder?(norm, policy: :ca_baseline)
      pol = Policy.coerce(policy)
      return false unless reasons_for(norm, policy: pol).empty?

      registrable = norm.psl&.domain
      return registrable != norm.psl.tld unless registrable.nil?

      norm.labels.size >= 2
    end

    # The registrable domain ("example.co.uk" from "www.example.co.uk"), or nil.
    def registrable_domain(subject, policy: :ca_baseline)
      normalize(subject, Policy.coerce(policy)).psl&.domain
    end

    # The public suffix ("co.uk" from "www.example.co.uk"), or nil.
    def public_suffix(subject, policy: :ca_baseline)
      normalize(subject, Policy.coerce(policy)).psl&.tld
    end

    # --- internals -------------------------------------------------------

    def classify(subject)
      if subject.start_with?("*.") then :wildcard
      elsif IP.ip?(subject) then :ip
      elsif IP.reverse_zone?(subject) then :reverse_zone
      else :hostname
      end
    end

    def parse_psl(unicode, policy)
      PublicSuffix.parse(unicode, default_rule: nil, ignore_private: !policy.include_private_suffixes)
    rescue PublicSuffix::Error
      nil
    end

    def hostname_reasons(norm, policy)
      errors = []
      name = norm.name

      # Dot-structure checks run on the pre-IDN name, because IDN conversion
      # silently drops empty edge labels and would hide a leading dot.
      errors << reason(:leading_dot, "starts with a dot") if name.start_with?(".")
      errors << reason(:trailing_dot, "ends with a dot") if name.end_with?(".")
      errors << reason(:empty_label, "has an empty label (consecutive or edge dots)") if name.include?("..")
      if !policy.allow_trailing_dot && norm.input.end_with?(".")
        errors << reason(:trailing_dot, "ends with a dot")
      end

      if norm.ascii.nil?
        errors << reason(:not_convertible, "is not convertible to a valid ASCII form")
        return errors.uniq
      end

      errors << reason(:too_long, "exceeds #{MAX_DOMAIN_LENGTH} characters") if norm.ascii.length > MAX_DOMAIN_LENGTH

      labels = norm.labels
      single_label = policy.allow_single_label && labels.size == 1
      errors << reason(:too_few_labels, "must have at least two labels") if labels.size < 2 && !single_label
      errors << reason(:too_many_labels, "exceeds #{MAX_LABELS} labels") if labels.size > MAX_LABELS

      pattern = policy.allow_underscore ? LDH_UNDERSCORE_LABEL : LDH_LABEL
      labels.each { |label| append_label_reason(errors, label, pattern) }

      append_tld_reasons(errors, norm, single_label, policy)

      if policy.require_single_script && IDN.mixed_script_unicode?(norm.unicode)
        errors << reason(:mixed_script, "mixes scripts within a label (possible homograph)")
      end

      errors.uniq
    end

    # TLD-level checks only apply when there is a TLD (i.e. more than one label,
    # or single-label names aren't permitted).
    def append_tld_reasons(errors, norm, single_label, policy)
      return if single_label

      tld = norm.labels.last
      errors << reason(:numeric_tld, "has an all-numeric TLD") if tld&.match?(NUMERIC)

      return unless norm.psl.nil?
      return if policy.allow_reserved_tld && reserved_tld?(tld)

      errors << reason(:unknown_tld, "has a TLD that is not in the Public Suffix List")
    end

    def reserved_tld?(tld)
      !tld.nil? && RESERVED_TLDS.include?(tld.downcase)
    end

    def append_label_reason(errors, label, pattern)
      if label.empty?
        errors << reason(:empty_label, "has an empty label (consecutive or edge dots)")
      elsif label.length > MAX_LABEL_LENGTH
        errors << reason(:label_too_long, "has a label longer than #{MAX_LABEL_LENGTH} characters: #{label.inspect}", label)
      elsif !label.match?(pattern)
        errors << reason(:label_invalid, "has an invalid label: #{label.inspect}", label)
      end
    end

    def reason(code, message, label = nil)
      Reason.new(code: code, message: message, label: label)
    end
  end
end
