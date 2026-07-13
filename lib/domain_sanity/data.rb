# frozen_string_literal: true

require "date"
require "public_suffix"
require "simpleidn"

module DomainSanity
  # A domain validator is only as correct as the reference data behind it, and
  # that data drifts: IANA revises the special-purpose IP registries and the
  # ICANN Public Suffix List changes constantly. Rather than let correctness rot
  # silently, DomainSanity records where its data came from and how old it is,
  # so callers can log it and CI can fail when it goes stale.
  #
  # The reserved-IP ranges in {IP} are vendored by hand; RESERVED_IP_SNAPSHOT is
  # the date they were last reconciled with the IANA registries. The Public
  # Suffix List and IDNA tables ship inside their respective gems, so their
  # "version" is the gem version. Refresh the IP snapshot with `rake data:sync`
  # (see the Rakefile) and bump the date below.
  module Data
    # Last time RESERVED_IPV4 / RESERVED_IPV6 were reconciled with
    # https://www.iana.org/assignments/iana-ipv4-special-registry and its IPv6
    # counterpart.
    RESERVED_IP_SNAPSHOT = Date.new(2026, 7, 1)

    # How old the IP snapshot may get before {stale?} reports true (~18 months).
    MAX_SNAPSHOT_AGE_DAYS = 548

    module_function

    # A snapshot of every data source's provenance, safe to log or serialize.
    def versions
      {
        reserved_ip_snapshot: RESERVED_IP_SNAPSHOT.iso8601,
        reserved_ip_age_days: age_days,
        public_suffix_gem: gem_version("PublicSuffix"),
        simpleidn_gem: gem_version("SimpleIDN")
      }
    end

    # True when the vendored IP snapshot is older than MAX_SNAPSHOT_AGE_DAYS.
    def stale?(today = Date.today)
      age_days(today) > MAX_SNAPSHOT_AGE_DAYS
    end

    def age_days(today = Date.today)
      (today - RESERVED_IP_SNAPSHOT).to_i
    end

    def gem_version(mod_name)
      mod = Object.const_get(mod_name)
      mod.const_defined?(:VERSION) ? mod.const_get(:VERSION) : nil
    rescue NameError
      nil
    end
  end
end
