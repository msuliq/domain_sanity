# frozen_string_literal: true

RSpec.describe DomainSanity::Policy do
  it "defaults every field to the strict choice (trailing dot excepted)" do
    policy = described_class.ca_baseline
    expect(policy.allow_underscore).to be(false)
    expect(policy.allow_single_label).to be(false)
    expect(policy.include_private_suffixes).to be(false)
    expect(policy.allow_reserved_tld).to be(false)
    expect(policy.require_single_script).to be(false)
    expect(policy.allow_trailing_dot).to be(true)
  end

  it "distinguishes :lenient from :dns_zone by allow_reserved_tld" do
    expect(described_class.dns_zone.allow_reserved_tld).to be(false)
    expect(described_class.lenient.allow_reserved_tld).to be(true)
    expect(described_class.lenient).not_to eq(described_class.dns_zone)
  end

  it "builds copies with #with without mutating the original" do
    base = described_class.ca_baseline
    permissive = base.with(allow_underscore: true)
    expect(permissive.allow_underscore).to be(true)
    expect(base.allow_underscore).to be(false)
  end

  it "is frozen and value-comparable" do
    expect(described_class.ca_baseline).to be_frozen
    expect(described_class.ca_baseline).to eq(described_class.new)
    expect(described_class.new(allow_underscore: true)).not_to eq(described_class.new)
  end

  it "rejects unknown fields" do
    expect { described_class.new(bogus: true) }.to raise_error(ArgumentError, /unknown policy option/)
  end

  describe ".coerce" do
    it "accepts a preset symbol, a Hash, a Policy, or nil" do
      expect(described_class.coerce(:dns_zone).allow_underscore).to be(true)
      expect(described_class.coerce(allow_underscore: true).allow_underscore).to be(true)
      pol = described_class.new(allow_single_label: true)
      expect(described_class.coerce(pol)).to equal(pol)
      expect(described_class.coerce(nil)).to eq(described_class.ca_baseline)
    end

    it "raises on an unknown preset or uncoercible value" do
      expect { described_class.coerce(:nope) }.to raise_error(ArgumentError, /unknown policy preset/)
      expect { described_class.coerce(42) }.to raise_error(ArgumentError, /cannot coerce/)
    end
  end
end
