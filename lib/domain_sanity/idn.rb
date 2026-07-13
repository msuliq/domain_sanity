# frozen_string_literal: true

require "set"
require "simpleidn"

module DomainSanity
  # Internationalized Domain Name helpers.
  #
  # Conversion between the ASCII (A-label / punycode) and Unicode (U-label)
  # forms is delegated to SimpleIDN, which implements IDNA2003-style punycode.
  # It is NOT a full UTS-46 / IDNA2008 processor: mapping of a handful of code
  # points (final sigma, ß, ZWJ/ZWNJ, deviation characters) differs from the
  # current standard. If you need IDNA2008 exactness, normalize upstream with a
  # UTS-46 library before handing names to DomainSanity. Length and label
  # validation here operate on the ASCII form regardless, so the wire-format
  # limits stay correct either way.
  #
  # Separately, {mixed_script?} provides a lightweight homograph guard: it flags
  # labels that combine scripts in ways a Unicode registry would not allow
  # (e.g. Latin mixed with Cyrillic). This is opt-in via Policy
  # (require_single_script) because legitimate names occasionally trip it.
  #
  # None of these helpers raise: unconvertible input comes back as nil so
  # callers can branch cleanly. Only SimpleIDN::ConversionError (a malformed
  # A-label) is swallowed.
  module IDN
    # Script groups that legitimately co-occur within one label, per the spirit
    # of UTS-39 "Highly Restrictive": a run may mix Latin with one East Asian
    # script family, but not, say, Latin with Cyrillic.
    ALLOWED_MULTI_SCRIPT = [
      Set[:latin, :han, :hiragana, :katakana], # Japanese
      Set[:latin, :han, :bopomofo],            # Chinese
      Set[:latin, :han, :hangul]               # Korean
    ].freeze

    # Scripts we can name. Anything letter-like outside this list collapses to
    # :other, which still participates in the "more than one script" test.
    SCRIPT_PATTERNS = {
      latin: /\p{Latin}/,
      greek: /\p{Greek}/,
      cyrillic: /\p{Cyrillic}/,
      armenian: /\p{Armenian}/,
      hebrew: /\p{Hebrew}/,
      arabic: /\p{Arabic}/,
      han: /\p{Han}/,
      hiragana: /\p{Hiragana}/,
      katakana: /\p{Katakana}/,
      hangul: /\p{Hangul}/,
      bopomofo: /\p{Bopomofo}/,
      thai: /\p{Thai}/,
      devanagari: /\p{Devanagari}/
    }.freeze

    module_function

    # Convert a name to its ASCII/punycode form. Returns nil for non-strings,
    # empty input, or input that cannot be encoded.
    def to_ascii(name)
      return nil unless name.is_a?(String)
      return nil if name.empty?

      SimpleIDN.to_ascii(name)
    rescue SimpleIDN::ConversionError
      nil
    end

    # Convert a name to its Unicode form. Returns nil for non-strings, empty
    # input, or input that cannot be decoded.
    def to_unicode(name)
      return nil unless name.is_a?(String)
      return nil if name.empty?

      SimpleIDN.to_unicode(name)
    rescue SimpleIDN::ConversionError
      nil
    end

    # True when the name (or any of its labels) uses the xn-- ACE prefix.
    def punycode?(name)
      return false unless name.is_a?(String)

      name.downcase.split(".").any? { |label| label.start_with?("xn--") }
    end

    # The set of scripts among the letters of a string (Common/Inherited and
    # non-letters are ignored). Unknown letters collapse to :other.
    def scripts(string)
      return Set.new unless string.is_a?(String)

      string.each_char.with_object(Set.new) do |char, found|
        next unless char.match?(/\p{L}/)

        name, = SCRIPT_PATTERNS.find { |_, pattern| char.match?(pattern) }
        found << (name || :other)
      end
    end

    # True when any label in the name mixes scripts in a way that reads as a
    # homograph risk. Operates on the Unicode form; an unconvertible name is not
    # flagged (there is nothing to compare). Mixing is judged per label, since
    # cross-label mixing (e.g. an xn-- label beside an ASCII one) is normal.
    def mixed_script?(name)
      mixed_script_unicode?(to_unicode(name) || name)
    end

    # As {mixed_script?}, but for a name already decoded to its Unicode form.
    # Callers that hold the U-label form (Name.normalize does) skip re-decoding.
    def mixed_script_unicode?(unicode)
      return false unless unicode.is_a?(String)

      unicode.split(".").any? { |label| label_mixed_script?(label) }
    end

    def label_mixed_script?(label)
      found = scripts(label)
      return false if found.size <= 1

      ALLOWED_MULTI_SCRIPT.none? { |allowed| found.subset?(allowed) }
    end
  end
end
