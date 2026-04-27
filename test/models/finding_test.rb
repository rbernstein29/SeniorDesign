require "test_helper"

class FindingTest < ActiveSupport::TestCase
  # ── severity_badge_class ─────────────────────────────────────────────────────

  test "severity_badge_class returns badge-critical for critical" do
    f = Finding.new(severity: "critical")
    assert_equal "badge-critical", f.severity_badge_class
  end

  test "severity_badge_class returns badge-critical for uppercase CRITICAL" do
    f = Finding.new(severity: "CRITICAL")
    assert_equal "badge-critical", f.severity_badge_class
  end

  test "severity_badge_class returns badge-high for high" do
    f = Finding.new(severity: "high")
    assert_equal "badge-high", f.severity_badge_class
  end

  test "severity_badge_class returns badge-medium for medium" do
    f = Finding.new(severity: "medium")
    assert_equal "badge-medium", f.severity_badge_class
  end

  test "severity_badge_class returns badge-low for low" do
    f = Finding.new(severity: "low")
    assert_equal "badge-low", f.severity_badge_class
  end

  test "severity_badge_class returns badge-low for unknown severity" do
    f = Finding.new(severity: "informational")
    assert_equal "badge-low", f.severity_badge_class
  end

  test "severity_badge_class returns badge-low for nil severity" do
    f = Finding.new(severity: nil)
    assert_equal "badge-low", f.severity_badge_class
  end

  # ── for_org scope ────────────────────────────────────────────────────────────

  test "for_org returns findings belonging to the given org" do
    acme_id = ActiveRecord::FixtureSet.identify(:acme)
    results = Finding.for_org(acme_id)
    assert results.any?, "Expected at least one finding for acme"
    results.each do |finding|
      assert_equal acme_id, finding.asset.organization_id
    end
  end

  test "for_org excludes findings from other orgs" do
    other_id = ActiveRecord::FixtureSet.identify(:other_org)
    acme_id  = ActiveRecord::FixtureSet.identify(:acme)
    results  = Finding.for_org(other_id)
    assert results.none? { |f| f.asset.organization_id == acme_id },
           "for_org(:other_org) should not include findings belonging to acme"
  end

  test "for_org returns empty when org has no findings" do
    results = Finding.for_org(-1)
    assert_empty results
  end
end
