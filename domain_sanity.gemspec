# frozen_string_literal: true

require_relative "lib/domain_sanity/version"

Gem::Specification.new do |spec|
  spec.name = "domain_sanity"
  spec.version = DomainSanity::VERSION
  spec.authors = ["Suleyman Musayev"]
  spec.email = ["slmusayev@gmail.com"]

  spec.summary = "Strict, standards-based domain name validation for certificate and PKI workflows"
  spec.description = "A small, fast Ruby gem for validating and inspecting domain names the way a " \
                     "certificate authority has to: RFC 1035 label rules, IDN/punycode round-tripping, " \
                     "Public Suffix List and TLD checks, CA/Browser Forum aware wildcard rules, plus " \
                     "IP address, private/reserved range, and reverse-zone detection. Two runtime " \
                     "dependencies, both pure Ruby."
  spec.homepage = "https://github.com/msuliq/domain_sanity"
  spec.license = "MIT"

  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata = {
    "rubygems_mfa_required" => "true",
    "homepage_uri" => spec.homepage,
    "source_code_uri" => "https://github.com/msuliq/domain_sanity",
    "changelog_uri" => "https://github.com/msuliq/domain_sanity/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "https://github.com/msuliq/domain_sanity/issues"
  }

  spec.files = Dir.chdir(__dir__) do
    Dir["{lib}/**/*", "LICENSE", "README.md", "CHANGELOG.md"]
  end

  spec.require_paths = ["lib"]

  # Runtime dependencies, deliberately kept to two lean, pure-Ruby gems.
  # IPAddr, Date, and Set come from the standard library and add nothing to install.
  spec.add_dependency "public_suffix", ">= 5.0"
  spec.add_dependency "simpleidn", ">= 0.2"
end
