# frozen_string_literal: true

RSpec.describe DomainSanity::Data do
  it "reports provenance for every data source" do
    versions = described_class.versions
    expect(versions[:reserved_ip_snapshot]).to eq(described_class::RESERVED_IP_SNAPSHOT.iso8601)
    expect(versions[:reserved_ip_age_days]).to be_a(Integer)
    expect(versions[:public_suffix_gem]).to be_a(String)
    expect(versions[:simpleidn_gem]).to be_a(String)
  end

  it "is not stale today (CI guard against silently rotting reference data)" do
    expect(described_class.stale?).to be(false)
  end

  it "reports stale? once the snapshot passes the age threshold" do
    future = described_class::RESERVED_IP_SNAPSHOT + described_class::MAX_SNAPSHOT_AGE_DAYS + 1
    expect(described_class.stale?(future)).to be(true)
  end
end
