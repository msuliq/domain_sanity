# frozen_string_literal: true

require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

task default: :spec

namespace :data do
  desc "Report the provenance and age of the vendored reference data"
  task :check do
    $LOAD_PATH.unshift File.expand_path("lib", __dir__)
    require "domain_sanity"

    DomainSanity.data_versions.each { |key, value| puts format("%-22s %s", key, value) }

    if DomainSanity::Data.stale?
      warn "\nThe reserved-IP snapshot is stale (> #{DomainSanity::Data::MAX_SNAPSHOT_AGE_DAYS} days). " \
           "Run `rake data:sync` and bump RESERVED_IP_SNAPSHOT."
      exit 1
    else
      puts "\nReserved-IP snapshot is current."
    end
  end

  desc "Reconcile the reserved-IP ranges with the IANA special-purpose registries"
  task :sync do
    # The reserved-IP ranges in lib/domain_sanity/ip.rb are vendored by hand.
    # To refresh them, compare against the authoritative registries:
    #
    #   IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry
    #   IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry
    #
    # Add or remove blocks in RESERVED_IPV4 / RESERVED_IPV6, then bump
    # DomainSanity::Data::RESERVED_IP_SNAPSHOT to today and run `rake data:check`.
    #
    # This task is intentionally manual: the registries are small and change
    # rarely, and pulling them at build time would add a network dependency to
    # an otherwise offline gem.
    puts <<~MSG
      Reconcile lib/domain_sanity/ip.rb against the IANA special-purpose registries:
        IPv4: https://www.iana.org/assignments/iana-ipv4-special-registry
        IPv6: https://www.iana.org/assignments/iana-ipv6-special-registry
      Then bump DomainSanity::Data::RESERVED_IP_SNAPSHOT and run `rake data:check`.
    MSG
  end
end
