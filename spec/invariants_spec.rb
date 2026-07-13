# frozen_string_literal: true

# Contracts the design promises, checked across a hand-picked corpus and a
# deterministic pseudo-random fuzz. These catch whole categories that
# example-based tests miss.
RSpec.describe "DomainSanity invariants" do
  def known_kinds
    %i[hostname wildcard ip reverse_zone nil empty whitespace not_a_string oversized]
  end

  def corpus
    [
      # valid hostnames
      "example.com", "www.example.co.uk", "a.b.c.example.com", "münchen.de",
      "例え.jp", "xn--mnchen-3ya.de", "example.com.",
      # invalid hostnames
      "-bad.example.com", "example..com", "example.123", "localhost", "com",
      "example.invalidtld", "_dmarc.example.com", "#{"a" * 64}.com", "example.com..",
      # other kinds
      "*.example.com", "*.co.uk", "192.0.2.10", "2606:4700::1111",
      "10.0.0.1", "1.2.0.192.in-addr.arpa", "0.ip6.arpa",
      # degenerate
      nil, "", "  ", "exa mple.com", ".",
      # non-strings must be handled, not crash
      123, :sym, [], {}
    ]
  end

  # A deterministic sample of arbitrary label-ish strings.
  def fuzz_names(count: 200, seed: 20_260_712)
    rng = Random.new(seed)
    alphabet = ("a".."z").to_a + ("0".."9").to_a + ["-", "_", "."]
    Array.new(count) do
      length = rng.rand(1..24)
      Array.new(length) { alphabet.sample(random: rng) }.join
    end
  end

  def all_inputs
    corpus + fuzz_names
  end

  it "holds: valid? == reasons.empty? (reasons is the single source of truth)" do
    all_inputs.each do |input|
      expect(DomainSanity.valid?(input)).to eq(DomainSanity.reasons(input).empty?),
        "mismatch for #{input.inspect}"
    end
  end

  it "holds: analyze(x).valid? == valid?(x) (entry points agree)" do
    all_inputs.each do |input|
      expect(DomainSanity.analyze(input).valid?).to eq(DomainSanity.valid?(input)),
        "mismatch for #{input.inspect}"
    end
  end

  it "holds: classification is total and drawn from the known set" do
    all_inputs.each do |input|
      expect(known_kinds).to include(DomainSanity.analyze(input).kind), "for #{input.inspect}"
    end
  end

  it "holds: at most one of wildcard?/ip?/reverse_zone? is true" do
    all_inputs.each do |input|
      subject = DomainSanity.analyze(input)
      flags = [subject.wildcard?, subject.ip?, subject.reverse_zone?].count(true)
      expect(flags).to be <= 1, "multiple kinds for #{input.inspect}"
    end
  end

  it "holds: valid? implies the subject is a host name" do
    all_inputs.each do |input|
      subject = DomainSanity.analyze(input)
      expect(subject.kind).to eq(:hostname) if subject.valid?
    end
  end

  it "holds: IDN A-label/U-label round-trips for valid names" do
    %w[münchen.de 例え.jp xn--mnchen-3ya.de example.com].each do |name|
      ascii = DomainSanity.to_ascii(name)
      expect(DomainSanity.to_ascii(DomainSanity.to_unicode(ascii))).to eq(ascii)
    end
  end

  it "never raises on arbitrary input" do
    all_inputs.each do |input|
      expect do
        DomainSanity.analyze(input).to_h
        DomainSanity.valid?(input)
        DomainSanity.reasons(input)
      end.not_to raise_error, "raised for #{input.inspect}"
    end
  end
end
