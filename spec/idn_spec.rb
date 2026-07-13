# frozen_string_literal: true

RSpec.describe DomainSanity::IDN do
  describe ".to_ascii / .to_unicode" do
    it "round-trips a Unicode name" do
      expect(described_class.to_ascii("münchen.de")).to eq("xn--mnchen-3ya.de")
      expect(described_class.to_unicode("xn--mnchen-3ya.de")).to eq("münchen.de")
    end

    it "returns nil for nil, empty, and non-strings instead of raising" do
      expect(described_class.to_ascii(nil)).to be_nil
      expect(described_class.to_ascii("")).to be_nil
      expect(described_class.to_ascii(123)).to be_nil
      expect(described_class.to_unicode(:sym)).to be_nil
    end

    it "returns nil for malformed punycode (SimpleIDN::ConversionError)" do
      expect(described_class.to_unicode("xn--bad-punycode-zz99")).to be_nil
    end
  end

  describe ".punycode?" do
    it "detects the xn-- prefix on any label" do
      expect(described_class.punycode?("www.xn--mnchen-3ya.de")).to be(true)
      expect(described_class.punycode?("example.com")).to be(false)
      expect(described_class.punycode?(nil)).to be(false)
    end
  end

  describe ".scripts / .mixed_script?" do
    it "collects the scripts of the letters, ignoring non-letters" do
      expect(described_class.scripts("abc123")).to eq(Set[:latin])
      expect(described_class.scripts("аbc")).to eq(Set[:cyrillic, :latin]) # leading Cyrillic "а"
    end

    it "flags confusable Latin/Cyrillic mixing per label" do
      expect(described_class.mixed_script?("аpple.com")).to be(true)
      expect(described_class.mixed_script?("pay-pаl.com")).to be(true)
    end

    it "permits single-script and legitimate multi-script labels" do
      expect(described_class.mixed_script?("münchen.de")).to be(false) # Latin only
      expect(described_class.mixed_script?("例え.jp")).to be(false)      # Japanese: Han + Hiragana
      expect(described_class.mixed_script?("xn--mnchen-3ya.de")).to be(false)
    end
  end
end
