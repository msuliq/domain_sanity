# frozen_string_literal: true

require_relative "name"
require_relative "ip"
require_relative "idn"
require_relative "policy"

module DomainSanity
  # A classified view of one subject string. {Subject.for} inspects the input
  # once and returns the concrete type that fits it - Hostname, Wildcard,
  # IPSubject, ReverseZone, or MalformedSubject - so a method that only makes
  # sense for one kind (registrable_domain for a host, public? for an IP) lives
  # only on that type instead of returning nil on a god-object.
  #
  # Facts are computed lazily and memoized, so asking one question is cheap and
  # asking many re-parses nothing. `valid?` means the same thing on every
  # subject and matches DomainSanity.valid? exactly: true only for a
  # structurally valid plain host name. Wildcards, IPs, and reverse zones are
  # not "valid" in that sense and expose their own predicates instead.
  class Subject
    attr_reader :input, :policy

    # Classify `input` under `policy` (a preset symbol, Hash, or Policy) and
    # return the matching Subject subclass.
    def self.for(input, policy: :ca_baseline)
      pol = Policy.coerce(policy)
      norm = Name.normalize(input, pol)
      klass = TYPES.fetch(norm.kind, MalformedSubject)
      klass.new(input, norm, pol)
    end

    def initialize(input, normalized, policy)
      @input = input
      @norm = normalized
      @policy = policy
    end

    def kind
      @norm.kind
    end

    # Only a structurally valid plain host name is "valid"; every other kind
    # overrides nothing and stays false. See Hostname.
    def valid?
      false
    end

    def hostname?
      false
    end

    def wildcard?
      false
    end

    def valid_wildcard?
      false
    end

    def ip?
      false
    end

    def reverse_zone?
      false
    end

    def reasons
      @reasons ||= Name.reasons_for(@norm, policy: @policy).freeze
    end

    def punycode?
      return @punycode if defined?(@punycode)

      @punycode = IDN.punycode?(@input)
    end

    def ascii
      return @ascii if defined?(@ascii)

      @ascii = IDN.to_ascii(@input)
    end

    def unicode
      return @unicode if defined?(@unicode)

      @unicode = IDN.to_unicode(@input)
    end

    # A uniform snapshot: every subject exposes the same keys, with nil where a
    # fact does not apply to this kind. (The typed *methods* stay kind-specific -
    # an IPSubject still has no #registrable_domain - but the serialized shape is
    # stable so downstream `present?`/`dig` checks work the same for any kind.)
    # Subclasses fill the optional slots via {type_facts}.
    def to_h
      {
        input: @input,
        kind: kind,
        valid: valid?,
        wildcard: wildcard?,
        valid_wildcard: valid_wildcard?,
        ip: ip?,
        reserved_ip: nil,
        public_ip: nil,
        reverse_zone: reverse_zone?,
        punycode: punycode?,
        ascii: ascii,
        unicode: unicode,
        registrable_domain: nil,
        public_suffix: nil,
        reasons: reasons.map(&:to_s)
      }.merge(type_facts)
    end

    # Kind-specific overrides for the optional to_h slots. Base has none.
    def type_facts
      {}
    end
  end

  # Shared to_h slots for the kinds that carry a registrable domain (Hostname
  # and Wildcard). Each including class supplies its own registrable_domain /
  # public_suffix; this just maps them into the uniform to_h shape.
  module RegistrableTypeFacts
    def type_facts
      {registrable_domain: registrable_domain, public_suffix: public_suffix}
    end
  end

  # A candidate fully-qualified host name.
  class Hostname < Subject
    include RegistrableTypeFacts

    def hostname?
      true
    end

    def valid?
      reasons.empty?
    end

    def registrable_domain
      @norm.psl&.domain
    end

    def public_suffix
      @norm.psl&.tld
    end
  end

  # A "*.something" wildcard name.
  class Wildcard < Subject
    include RegistrableTypeFacts

    def wildcard?
      true
    end

    # Baseline-Requirements-valid wildcard. A wildcard is never a plain
    # host name, so #valid? stays false; this is the predicate to ask. Derived
    # from the single normalized remainder, so nothing re-parses.
    def valid_wildcard?
      return @valid_wildcard if defined?(@valid_wildcard)

      @valid_wildcard = @input.count("*") == 1 &&
        Name.valid_wildcard_remainder?(remainder, policy: @policy)
    end

    # The registrable domain / public suffix of the wildcard's base name.
    def registrable_domain
      remainder.psl&.domain
    end

    def public_suffix
      remainder.psl&.tld
    end

    private

    def remainder
      @remainder ||= Name.normalize(@input[2..], @policy)
    end
  end

  # A single IPv4 or IPv6 host address.
  class IPSubject < Subject
    def ip?
      true
    end

    def reserved?
      return @reserved if defined?(@reserved)

      @reserved = IP.reserved?(@input)
    end
    alias_method :reserved_ip?, :reserved?

    def public?
      return @public if defined?(@public)

      @public = IP.public?(@input)
    end
    alias_method :public_ip?, :public?

    def type_facts
      {reserved_ip: reserved?, public_ip: public?}
    end
  end

  # An in-addr.arpa / ip6.arpa reverse-DNS zone name.
  class ReverseZone < Subject
    def reverse_zone?
      true
    end
  end

  # nil, empty, or whitespace-bearing input - no meaningful structure.
  class MalformedSubject < Subject
  end

  class Subject
    TYPES = {
      hostname: Hostname,
      wildcard: Wildcard,
      ip: IPSubject,
      reverse_zone: ReverseZone
    }.freeze
  end
end
