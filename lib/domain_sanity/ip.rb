# frozen_string_literal: true

require "ipaddr"

module DomainSanity
  # IP address helpers.
  #
  # A certificate authority has to tell three things apart: a public IP that
  # may be certifiable, a private or otherwise reserved IP that the CA/Browser
  # Forum Baseline Requirements forbid issuing for, and a reverse-DNS zone name
  # (in-addr.arpa / ip6.arpa) that is not an issuable host name at all. These
  # helpers answer all three from the public IANA special-purpose registries.
  #
  # Only single host addresses count as IPs here: prefix / CIDR notation such
  # as "10.0.0.0/8" is deliberately rejected, since a network block is not a
  # host name or a certificate subject.
  module IP
    # IPv4 special-purpose ranges. These are not globally routable public
    # addresses and must not appear in a public certificate.
    #
    # Source: IANA IPv4 Special-Purpose Address Registry
    # (https://www.iana.org/assignments/iana-ipv4-special-registry). This list
    # is maintained by hand and should be re-synced with the registry when
    # IANA adds or removes a block.
    RESERVED_IPV4 = [
      "0.0.0.0/8",         # "This host on this network" (RFC 1122)
      "10.0.0.0/8",        # Private-use (RFC 1918)
      "100.64.0.0/10",     # Shared address space / CGN (RFC 6598)
      "127.0.0.0/8",       # Loopback (RFC 1122)
      "169.254.0.0/16",    # Link-local (RFC 3927)
      "172.16.0.0/12",     # Private-use (RFC 1918)
      "192.0.0.0/24",      # IETF protocol assignments (RFC 6890)
      "192.0.2.0/24",      # Documentation TEST-NET-1 (RFC 5737)
      "192.31.196.0/24",   # AS112-v4 (RFC 7535)
      "192.52.193.0/24",   # AMT (RFC 7450)
      "192.88.99.0/24",    # 6to4 relay anycast (RFC 3068, deprecated)
      "192.168.0.0/16",    # Private-use (RFC 1918)
      "192.175.48.0/24",   # Direct Delegation AS112 Service (RFC 7534)
      "198.18.0.0/15",     # Benchmarking (RFC 2544)
      "198.51.100.0/24",   # Documentation TEST-NET-2 (RFC 5737)
      "203.0.113.0/24",    # Documentation TEST-NET-3 (RFC 5737)
      "224.0.0.0/4",       # Multicast (RFC 5771)
      "240.0.0.0/4",       # Reserved for future use (RFC 1112)
      "255.255.255.255/32" # Limited broadcast (RFC 8190)
    ].freeze

    # IPv6 special-purpose ranges.
    #
    # Source: IANA IPv6 Special-Purpose Address Registry
    # (https://www.iana.org/assignments/iana-ipv6-special-registry). Re-sync
    # with the registry when IANA adds or removes a block. Note that 2001::/23
    # is a superset covering several individually registered protocol blocks
    # (Teredo, benchmarking, AMT, ORCHIDv2, and friends).
    RESERVED_IPV6 = [
      "::/128",            # Unspecified address (RFC 4291)
      "::1/128",           # Loopback (RFC 4291)
      "::ffff:0:0/96",     # IPv4-mapped (RFC 4291)
      "64:ff9b::/96",      # IPv4/IPv6 translation (RFC 6052)
      "64:ff9b:1::/48",    # Local-use IPv4/IPv6 translation (RFC 8215)
      "100::/64",          # Discard-only (RFC 6666)
      "2001::/23",         # IETF protocol assignments (RFC 2928)
      "2001:db8::/32",     # Documentation (RFC 3849)
      "2002::/16",         # 6to4 (RFC 3056, deprecated)
      "2620:4f:8000::/48", # Direct Delegation AS112 Service (RFC 7534)
      "3fff::/20",         # Documentation (RFC 9637)
      "5f00::/16",         # Segment Routing (SRv6) SIDs (RFC 9602)
      "fc00::/7",          # Unique local addresses (RFC 4193)
      "fe80::/10",         # Link-local (RFC 4291)
      "ff00::/8"           # Multicast (RFC 4291)
    ].freeze

    # Parse the CIDR strings once so membership checks don't reparse them on
    # every call.
    RESERVED_IPV4_NETS = RESERVED_IPV4.map { |cidr| IPAddr.new(cidr) }.freeze
    RESERVED_IPV6_NETS = RESERVED_IPV6.map { |cidr| IPAddr.new(cidr) }.freeze

    # Characters that can appear in an IPv4 or IPv6 literal. Anything else means
    # the string can't be an address, so we skip IPAddr.new (which signals a
    # non-address by raising) - most host names contain a letter outside a-f and
    # never reach that hot-path exception.
    IP_CHARS = /\A[0-9a-f:.]+\z/i

    module_function

    # True when subject parses as a single IPv4 or IPv6 host address. Prefix /
    # CIDR notation and non-strings return false.
    def ip?(subject)
      !parse(subject).nil?
    end

    # True when subject is a private or otherwise reserved (non-public) IP.
    # Non-IP input returns false.
    def reserved?(subject)
      addr = parse(subject)
      return false if addr.nil?

      reserved_address?(addr)
    end

    # True when subject is a routable, non-reserved public IP. Non-IP input
    # returns false. Parses once, unlike ip? && !reserved?.
    def public?(subject)
      addr = parse(subject)
      return false if addr.nil?

      !reserved_address?(addr)
    end

    # True when subject is a reverse-DNS zone name rather than a host name.
    def reverse_zone?(subject)
      return false unless subject.is_a?(String)

      normalized = subject.downcase.chomp(".")
      normalized == "in-addr.arpa" || normalized == "ip6.arpa" ||
        normalized.end_with?(".in-addr.arpa") || normalized.end_with?(".ip6.arpa")
    end

    # Parse to an IPAddr for a single host address, or nil when the input is
    # not one (including CIDR / prefix notation and non-strings).
    def parse(subject)
      return nil unless subject.is_a?(String)
      return nil if subject.include?("/")
      return nil unless subject.match?(IP_CHARS)

      IPAddr.new(subject)
    rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError
      nil
    end

    # Whether an already-parsed IPAddr falls in any reserved range.
    def reserved_address?(addr)
      nets = addr.ipv4? ? RESERVED_IPV4_NETS : RESERVED_IPV6_NETS
      nets.any? { |net| net.include?(addr) }
    end
  end
end
