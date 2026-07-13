# frozen_string_literal: true

RSpec.describe DomainSanity::IP do
  describe ".ip?" do
    it "accepts single IPv4 and IPv6 host addresses" do
      expect(described_class.ip?("192.0.2.10")).to be(true)
      expect(described_class.ip?("2606:4700:4700::1111")).to be(true)
    end

    it "rejects CIDR / prefix notation and non-strings" do
      expect(described_class.ip?("10.0.0.0/8")).to be(false)
      expect(described_class.ip?("::/0")).to be(false)
      expect(described_class.ip?(nil)).to be(false)
      expect(described_class.ip?(42)).to be(false)
    end
  end

  describe ".reserved? / .public?" do
    it "agrees that a routable address is public and not reserved" do
      expect(described_class.reserved?("1.1.1.1")).to be(false)
      expect(described_class.public?("1.1.1.1")).to be(true)
    end

    it "agrees that a private address is reserved and not public" do
      expect(described_class.reserved?("10.0.0.1")).to be(true)
      expect(described_class.public?("10.0.0.1")).to be(false)
    end

    it "treats non-IP and CIDR input as neither reserved nor public" do
      expect(described_class.reserved?("example.com")).to be(false)
      expect(described_class.public?("example.com")).to be(false)
      expect(described_class.reserved?("10.0.0.0/8")).to be(false)
    end
  end

  describe ".reverse_zone?" do
    it "matches in-addr.arpa and ip6.arpa, with or without a trailing dot" do
      expect(described_class.reverse_zone?("1.2.0.192.in-addr.arpa")).to be(true)
      expect(described_class.reverse_zone?("in-addr.arpa.")).to be(true)
      expect(described_class.reverse_zone?("0.ip6.arpa")).to be(true)
      expect(described_class.reverse_zone?("example.com")).to be(false)
      expect(described_class.reverse_zone?(nil)).to be(false)
    end
  end
end
