# frozen_string_literal: true

RSpec.describe DomainSanity::Name do
  describe ".normalize" do
    it "strips exactly one trailing root dot" do
      expect(described_class.normalize("example.com.").name).to eq("example.com")
      expect(described_class.normalize("example.com..").name).to eq("example.com.")
    end

    it "classifies without doing IDN/PSL work for non-hostname kinds" do
      norm = described_class.normalize("192.0.2.1")
      expect(norm.kind).to eq(:ip)
      expect(norm.ascii).to be_nil
      expect(norm.psl).to be_nil
    end

    it "populates the hostname view once" do
      norm = described_class.normalize("www.example.co.uk")
      expect(norm.kind).to eq(:hostname)
      expect(norm.ascii).to eq("www.example.co.uk")
      expect(norm.labels).to eq(%w[www example co uk])
      expect(norm.psl.domain).to eq("example.co.uk")
    end

    it "resolves suffixes as ICANN-only by default and private when the policy says so" do
      icann = described_class.normalize("foo.github.io", DomainSanity::Policy.ca_baseline)
      private_ok = described_class.normalize("foo.github.io", DomainSanity::Policy.dns_zone)
      expect(icann.psl.tld).to eq("io")
      expect(private_ok.psl.tld).to eq("github.io")
    end
  end

  describe ".valid_tld?" do
    it "recognizes multi-label suffixes and rejects registrable names" do
      expect(described_class.valid_tld?("co.uk")).to be(true)
      expect(described_class.valid_tld?("example.co.uk")).to be(false)
    end
  end

  describe ".reasons" do
    it "reports numeric and unknown TLDs distinctly, with the offending label" do
      codes = described_class.reasons("example.123").map(&:code)
      expect(codes).to include(:numeric_tld, :unknown_tld)
      reason = described_class.reasons("#{"a" * 64}.com").find { |r| r.code == :label_too_long }
      expect(reason.label).to eq("a" * 64)
    end

    it "adds a trailing-dot reason only when the policy forbids it" do
      expect(described_class.reasons("example.com.").map(&:code)).to be_empty
      forbidding = described_class.reasons("example.com.", policy: {allow_trailing_dot: false})
      expect(forbidding.map(&:code)).to include(:trailing_dot)
    end

    it "adds a mixed_script reason under require_single_script" do
      codes = described_class.reasons("аpple.com", policy: {require_single_script: true}).map(&:code)
      expect(codes).to eq([:mixed_script])
    end
  end
end
