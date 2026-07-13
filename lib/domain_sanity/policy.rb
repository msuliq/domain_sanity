# frozen_string_literal: true

module DomainSanity
  # What counts as "valid" depends on who is asking. A certificate authority,
  # a DNS zone editor, and a lenient form validator disagree about underscores,
  # single-label names, private Public Suffix List entries, and script mixing.
  #
  # Policy captures those choices as data instead of letting them accrete as
  # boolean keyword arguments on every method. Pass a preset symbol, a Hash of
  # overrides, or a Policy instance anywhere a `policy:` argument is accepted;
  # {coerce} turns all three into a Policy.
  #
  #   DomainSanity.valid?("_dmarc.example.com", policy: :dns_zone)
  #   DomainSanity.valid?("host", policy: { allow_single_label: true })
  #
  # Policy only governs how a *host name* is judged; it never makes valid?
  # accept an IP, wildcard, or reverse-zone subject (those are distinct kinds
  # with their own predicates).
  class Policy
    # Each field defaults to the strict (CA-style) choice: false, except
    # allow_trailing_dot, since a single root dot denotes the same name.
    DEFAULTS = {
      allow_underscore: false,         # permit "_" in labels (RFC 952/1123 forbid it)
      allow_single_label: false,       # permit a bare host with no TLD ("intranet")
      allow_trailing_dot: true,        # accept & normalize one trailing root dot
      include_private_suffixes: false, # treat private PSL entries (github.io) as suffixes
      allow_reserved_tld: false,       # accept RFC 6761/6762/7686 special-use TLDs (.test, .local, .onion, .internal)
      require_single_script: false     # reject confusable mixed-script IDN labels
    }.freeze

    FIELDS = DEFAULTS.keys.freeze

    # The names of the built-in presets.
    PRESET_NAMES = %i[ca_baseline dns_zone lenient].freeze

    attr_reader(*FIELDS)

    def initialize(**opts)
      unknown = opts.keys - FIELDS
      raise ArgumentError, "unknown policy option(s): #{unknown.join(", ")}" unless unknown.empty?

      DEFAULTS.each { |field, default| instance_variable_set(:"@#{field}", opts.fetch(field, default)) }
      freeze
    end

    # A copy with some fields overridden.
    def with(**overrides)
      self.class.new(**to_h.merge(overrides))
    end

    def to_h
      FIELDS.to_h { |field| [field, public_send(field)] }
    end

    def ==(other)
      other.is_a?(Policy) && other.to_h == to_h
    end
    alias_method :eql?, :==

    def hash
      to_h.hash
    end

    class << self
      # Strict, certificate-authority-style defaults.
      def ca_baseline
        new
      end

      # DNS zone editing: underscores, single-label hosts, and private suffixes
      # are all fine here. Reserved special-use TLDs are still rejected - a real
      # zone shouldn't contain them.
      def dns_zone
        new(allow_underscore: true, allow_single_label: true, include_private_suffixes: true)
      end

      # Everything permissive, including RFC 6761/6762/7686 special-use TLDs
      # (.test, .local, .onion, .internal). Script safety stays off to avoid
      # false positives.
      def lenient
        new(
          allow_underscore: true,
          allow_single_label: true,
          include_private_suffixes: true,
          allow_reserved_tld: true
        )
      end

      def presets
        PRESET_NAMES
      end

      def preset(name)
        case name
        when :ca_baseline then ca_baseline
        when :dns_zone then dns_zone
        when :lenient then lenient
        else raise ArgumentError, "unknown policy preset: #{name.inspect}"
        end
      end

      # Turn a Symbol preset, Hash of overrides, Policy, or nil into a Policy.
      def coerce(arg)
        case arg
        when Policy then arg
        when Symbol then preset(arg)
        when Hash then ca_baseline.with(**arg)
        when nil then ca_baseline
        else raise ArgumentError, "cannot coerce #{arg.inspect} into a Policy"
        end
      end
    end
  end
end
