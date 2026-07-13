# frozen_string_literal: true

RSpec.describe DomainSanity do
  describe ".valid?" do
    it "accepts ordinary and internationalized domains" do
      expect(described_class.valid?("example.com")).to be(true)
      expect(described_class.valid?("a.b.example.co.uk")).to be(true)
      expect(described_class.valid?("xn--mnchen-3ya.de")).to be(true)
      expect(described_class.valid?("münchen.de")).to be(true)
      expect(described_class.valid?("例え.jp")).to be(true)
    end

    it "rejects nil, empty, and whitespace" do
      expect(described_class.valid?(nil)).to be(false)
      expect(described_class.valid?("")).to be(false)
      expect(described_class.valid?("exa mple.com")).to be(false)
    end

    it "rejects unknown TLDs, single labels, and all-numeric TLDs" do
      expect(described_class.valid?("example.thistlddoesnotexist")).to be(false)
      expect(described_class.valid?("localhost")).to be(false)
      expect(described_class.valid?("com")).to be(false)
      expect(described_class.valid?("example.123")).to be(false)
    end

    it "rejects hyphen and length violations" do
      expect(described_class.valid?("-example.com")).to be(false)
      expect(described_class.valid?("example-.com")).to be(false)
      expect(described_class.valid?("#{"a" * 64}.com")).to be(false)
      expect(described_class.valid?("#{"#{"a" * 60}." * 5}com")).to be(false)
    end

    it "accepts a single trailing (root) dot but rejects a doubled one" do
      expect(described_class.valid?("example.com.")).to be(true)
      expect(described_class.valid?("example.com..")).to be(false)
    end

    it "does not treat wildcards, IPs, or reverse zones as plain valid domains" do
      expect(described_class.valid?("*.example.com")).to be(false)
      expect(described_class.valid?("192.0.2.10")).to be(false)
      expect(described_class.valid?("1.2.0.192.in-addr.arpa")).to be(false)
    end
  end

  describe "policy" do
    it "rejects underscores under :ca_baseline but accepts them when the policy allows" do
      expect(described_class.valid?("_dmarc.example.com")).to be(false)
      expect(described_class.valid?("_dmarc.example.com", policy: :dns_zone)).to be(true)
      expect(described_class.valid?("_dmarc.example.com", policy: {allow_underscore: true})).to be(true)
    end

    it "accepts single-label hosts only when the policy allows" do
      expect(described_class.valid?("intranet-host")).to be(false)
      expect(described_class.valid?("intranet-host", policy: :dns_zone)).to be(true)
    end

    it "honors private public suffixes when asked" do
      expect(described_class.public_suffix("foo.github.io")).to eq("io")
      expect(described_class.public_suffix("foo.github.io", policy: :dns_zone)).to eq("github.io")
    end

    it "accepts special-use TLDs only under a policy that allows reserved TLDs" do
      expect(described_class.valid?("foo.test")).to be(false)
      expect(described_class.valid?("foo.test", policy: :dns_zone)).to be(false)
      expect(described_class.valid?("foo.test", policy: :lenient)).to be(true)
      expect(described_class.valid?("host.local", policy: :lenient)).to be(true)
      expect(described_class.valid?("svc.internal", policy: {allow_reserved_tld: true})).to be(true)
      # A genuinely unknown TLD is still rejected, even leniently.
      expect(described_class.valid?("foo.invalidtld", policy: :lenient)).to be(false)
    end

    it "does not synthesize PSL data for a reserved TLD" do
      expect(described_class.public_suffix("foo.test", policy: :lenient)).to be_nil
    end

    it "can require single-script labels" do
      cyrillic = "аpple.com" # leading Cyrillic "а"
      expect(described_class.valid?(cyrillic)).to be(true)
      expect(described_class.valid?(cyrillic, policy: {require_single_script: true})).to be(false)
      expect(described_class.valid?("münchen.de", policy: {require_single_script: true})).to be(true)
    end
  end

  describe ".reasons" do
    it "is empty for a valid domain and structured otherwise" do
      expect(described_class.reasons("example.com")).to be_empty
      reasons = described_class.reasons("-bad.example.123")
      expect(reasons.map(&:code)).to include(:label_invalid, :numeric_tld, :unknown_tld)
      expect(reasons.find { |r| r.code == :label_invalid }.label).to eq("-bad")
    end

    it "gives a single, specific reason for non-hostname kinds" do
      expect(described_class.reasons("192.0.2.10").map(&:code)).to eq([:ip_address])
      expect(described_class.reasons("1.2.0.192.in-addr.arpa").map(&:code)).to eq([:reverse_zone])
      expect(described_class.reasons("*.example.com").map(&:code)).to eq([:wildcard])
    end
  end

  describe ".valid_tld?" do
    it "is true only when the argument is itself a public suffix" do
      expect(described_class.valid_tld?("com")).to be(true)
      expect(described_class.valid_tld?("co.uk")).to be(true)
      expect(described_class.valid_tld?("example.com")).to be(false)
      expect(described_class.valid_tld?("thistlddoesnotexist")).to be(false)
      expect(described_class.valid_tld?(nil)).to be(false)
    end
  end

  describe ".valid_wildcard?" do
    it "accepts a wildcard on a registrable domain" do
      expect(described_class.valid_wildcard?("*.example.com")).to be(true)
      expect(described_class.valid_wildcard?("*.foo.example.co.uk")).to be(true)
    end

    it "rejects bare suffixes, embedded, and multiple wildcards" do
      expect(described_class.valid_wildcard?("*.com")).to be(false)
      expect(described_class.valid_wildcard?("*.co.uk")).to be(false)
      expect(described_class.valid_wildcard?("ba*.example.com")).to be(false)
      expect(described_class.valid_wildcard?("*.*.example.com")).to be(false)
      expect(described_class.valid_wildcard?("example.com")).to be(false)
    end
  end

  describe "IP handling" do
    it "detects host addresses and rejects CIDR" do
      expect(described_class.ip?("192.0.2.10")).to be(true)
      expect(described_class.ip?("2606:4700:4700::1111")).to be(true)
      expect(described_class.ip?("example.com")).to be(false)
      expect(described_class.ip?("10.0.0.0/8")).to be(false)
    end

    it "flags reserved ranges, including ones added from current IANA registries" do
      expect(described_class.reserved_ip?("10.0.0.1")).to be(true)
      expect(described_class.reserved_ip?("fe80::1")).to be(true)
      expect(described_class.reserved_ip?("192.31.196.5")).to be(true)
      expect(described_class.reserved_ip?("3fff::1")).to be(true)
      expect(described_class.reserved_ip?("5f00::1")).to be(true)
    end

    it "treats a routable address as public and detects reverse zones" do
      expect(described_class.public_ip?("1.1.1.1")).to be(true)
      expect(described_class.public_ip?("10.0.0.1")).to be(false)
      expect(described_class.reverse_zone?("1.2.0.192.in-addr.arpa")).to be(true)
      expect(described_class.reverse_zone?("example.com")).to be(false)
    end
  end

  describe ".to_ascii / .to_unicode / .mixed_script?" do
    it "round-trips an IDN and fails soft on garbage" do
      ascii = described_class.to_ascii("münchen.de")
      expect(ascii).to eq("xn--mnchen-3ya.de")
      expect(described_class.to_unicode(ascii)).to eq("münchen.de")
      expect(described_class.to_ascii(nil)).to be_nil
      expect(described_class.to_unicode("xn--bad-punycode-zz99")).to be_nil
    end

    it "flags Latin/Cyrillic mixing but not legitimate combinations" do
      expect(described_class.mixed_script?("аpple.com")).to be(true)
      expect(described_class.mixed_script?("münchen.de")).to be(false)
      expect(described_class.mixed_script?("例え.jp")).to be(false)
    end
  end

  describe ".analyze" do
    it "returns the typed subject for each kind" do
      expect(described_class.analyze("www.example.co.uk")).to be_a(DomainSanity::Hostname)
      expect(described_class.analyze("*.example.com")).to be_a(DomainSanity::Wildcard)
      expect(described_class.analyze("10.0.0.1")).to be_a(DomainSanity::IPSubject)
      expect(described_class.analyze("1.2.0.192.in-addr.arpa")).to be_a(DomainSanity::ReverseZone)
      expect(described_class.analyze(nil)).to be_a(DomainSanity::MalformedSubject)
    end
  end

  describe ".data_versions" do
    it "reports the reserved-IP snapshot and gem versions" do
      versions = described_class.data_versions
      expect(versions[:reserved_ip_snapshot]).to match(/\A\d{4}-\d{2}-\d{2}\z/)
      expect(versions[:public_suffix_gem]).to be_a(String)
    end
  end

  describe "regression: previously reported findings" do
    it "does not treat a reverse zone as a valid issuable domain" do
      expect(described_class.valid?("1.2.0.192.in-addr.arpa")).to be(false)
      expect(described_class.analyze("1.2.0.192.in-addr.arpa").valid?).to be(false)
    end

    it "answers valid_tld? honestly for real TLDs" do
      expect(described_class.valid_tld?("com")).to be(true)
      expect(described_class.valid_tld?("example.com")).to be(false)
    end

    it "does not shadow Object#inspect on the module" do
      expect { described_class.inspect }.not_to raise_error
      expect(described_class.inspect).to include("DomainSanity")
    end

    it "rejects CIDR notation from ip?" do
      expect(described_class.ip?("10.0.0.0/8")).to be(false)
    end

    it "rejects oversized input up front without heavy processing (DoS guard)" do
      huge = "a" * 500_000
      elapsed = Benchmark.realtime { @codes = described_class.reasons(huge).map(&:code) }
      expect(@codes).to eq([:input_too_long])
      expect(described_class.valid?(huge)).to be(false)
      expect(described_class.analyze(huge).kind).to eq(:oversized)
      # With the guard this short-circuits; without it, 500 KB through IDN/PSL
      # takes hundreds of ms.
      expect(elapsed).to be < 0.05
    end

    it "does not reject valid names that sit below the byte cap" do
      long_ascii = "#{(["a" * 49] * 4).join(".")}.com" # ~203 chars, valid FQDN
      expect(long_ascii.bytesize).to be <= DomainSanity::Name::MAX_INPUT_BYTES
      expect(described_class.valid?(long_ascii)).to be(true)
      expect(described_class.valid?("例え.jp")).to be(true) # multibyte IDN
    end

    it "handles non-String input without raising (returns false / :not_a_string)" do
      [123, :sym, [], {}, 3.14].each do |bad|
        expect { described_class.valid?(bad) }.not_to raise_error
        expect(described_class.valid?(bad)).to be(false)
        expect(described_class.reasons(bad).map(&:code)).to eq([:not_a_string])
        expect(described_class.analyze(bad).kind).to eq(:not_a_string)
      end
    end

    it "lets a wildcard sit on a reserved-TLD name when the policy allows reserved TLDs" do
      # foo.test is valid under :lenient, so *.foo.test should be too.
      expect(described_class.valid?("foo.test", policy: :lenient)).to be(true)
      expect(described_class.valid_wildcard?("*.foo.test", policy: :lenient)).to be(true)
      # but not a bare reserved TLD, and not under a policy that rejects them.
      expect(described_class.valid_wildcard?("*.test", policy: :lenient)).to be(false)
      expect(described_class.valid_wildcard?("*.foo.test")).to be(false)
    end
  end
end
