# frozen_string_literal: true

RSpec.describe DomainSanity::Subject do
  describe ".for" do
    it "returns the concrete type for each kind" do
      expect(described_class.for("www.example.com")).to be_a(DomainSanity::Hostname)
      expect(described_class.for("*.example.com")).to be_a(DomainSanity::Wildcard)
      expect(described_class.for("192.0.2.1")).to be_a(DomainSanity::IPSubject)
      expect(described_class.for("1.2.0.192.in-addr.arpa")).to be_a(DomainSanity::ReverseZone)
      expect(described_class.for(nil)).to be_a(DomainSanity::MalformedSubject)
      expect(described_class.for("")).to be_a(DomainSanity::MalformedSubject)
    end
  end

  describe "type-specific methods live only where they apply" do
    it "gives a Hostname a registrable domain but not an IPSubject" do
      expect(described_class.for("www.example.co.uk").registrable_domain).to eq("example.co.uk")
      expect(described_class.for("10.0.0.1")).not_to respond_to(:registrable_domain)
    end

    it "gives an IPSubject reserved?/public? but not a Hostname" do
      ip = described_class.for("10.0.0.1")
      expect(ip.reserved?).to be(true)
      expect(ip.public?).to be(false)
      expect(described_class.for("example.com")).not_to respond_to(:reserved?)
    end
  end

  describe "#valid?" do
    it "is true only for a structurally valid host name, false for other kinds" do
      expect(described_class.for("example.com").valid?).to be(true)
      expect(described_class.for("*.example.com").valid?).to be(false)
      expect(described_class.for("10.0.0.1").valid?).to be(false)
      expect(described_class.for("1.2.0.192.in-addr.arpa").valid?).to be(false)
      expect(described_class.for(nil).valid?).to be(false)
    end
  end

  describe "Wildcard" do
    it "reports valid_wildcard? without calling itself valid" do
      wc = described_class.for("*.example.com")
      expect(wc.valid?).to be(false)
      expect(wc.wildcard?).to be(true)
      expect(wc.valid_wildcard?).to be(true)
      expect(wc.registrable_domain).to eq("example.com")
    end
  end

  describe "lazy memoization" do
    it "computes reasons once and does not re-parse on repeated reads" do
      subject = described_class.for("www.example.co.uk")
      expect(subject.valid?).to be(true) # warms the memo
      expect(subject.reasons).to be_frozen
      expect(DomainSanity::Name).not_to receive(:reasons_for)
      3.times { expect(subject.valid?).to be(true) }
    end

    it "memoizes a false result too" do
      subject = described_class.for("nope.invalidtld")
      expect(subject.valid?).to be(false)
      expect(DomainSanity::Name).not_to receive(:reasons_for)
      2.times { expect(subject.valid?).to be(false) }
    end
  end

  describe "#to_h" do
    it "fills the relevant slots per kind" do
      host = described_class.for("www.example.co.uk").to_h
      expect(host).to include(kind: :hostname, valid: true, registrable_domain: "example.co.uk")

      ip = described_class.for("10.0.0.1").to_h
      expect(ip).to include(kind: :ip, ip: true, reserved_ip: true, public_ip: false)
    end

    it "exposes a uniform key set for every kind (nil where N/A)" do
      keys = described_class.for("www.example.co.uk").to_h.keys
      ["*.example.com", "10.0.0.1", "1.2.0.192.in-addr.arpa", nil, 123].each do |input|
        expect(described_class.for(input).to_h.keys).to eq(keys), "for #{input.inspect}"
      end
      # A slot that does not apply to the kind is present and nil, not absent.
      expect(described_class.for("10.0.0.1").to_h).to include(registrable_domain: nil)
      expect(described_class.for("www.example.co.uk").to_h).to include(reserved_ip: nil)
    end

    it "keeps the methods themselves kind-specific even though to_h is uniform" do
      expect(described_class.for("10.0.0.1")).not_to respond_to(:registrable_domain)
      expect(described_class.for("example.com")).not_to respond_to(:reserved?)
    end
  end
end
