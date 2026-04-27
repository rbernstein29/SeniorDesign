require "test_helper"

class ScanProfileTest < ActiveSupport::TestCase
  # ── validations ──────────────────────────────────────────────────────────────

  test "valid profile saves successfully" do
    profile = ScanProfile.new(
      name: "Test Profile",
      organization_id: ActiveRecord::FixtureSet.identify(:acme)
    )
    assert profile.valid?
  end

  test "name is required" do
    profile = ScanProfile.new(organization_id: ActiveRecord::FixtureSet.identify(:acme))
    assert_not profile.valid?
    assert_includes profile.errors[:name], "can't be blank"
  end

  # ── exploits method ──────────────────────────────────────────────────────────

  test "exploits returns empty relation when exploit_ids is empty" do
    profile = scan_profiles(:profile_one)
    profile.update!(exploit_ids: [])
    assert_empty profile.exploits
  end

  test "exploits returns matching exploits when exploit_ids is set" do
    exploit = exploits(:exploit_one)
    profile = scan_profiles(:profile_one)
    profile.update!(exploit_ids: [exploit.id])
    assert_includes profile.exploits, exploit
  end

  test "exploits returns only the exploits in exploit_ids" do
    e1 = exploits(:exploit_one)
    e2 = exploits(:exploit_two)
    profile = scan_profiles(:profile_one)
    profile.update!(exploit_ids: [e1.id])
    assert_includes profile.exploits, e1
    assert_not_includes profile.exploits, e2
  end

  # ── belongs_to organization ───────────────────────────────────────────────────

  test "belongs to organization" do
    profile = scan_profiles(:profile_one)
    assert_instance_of Organization, profile.organization
  end

  test "for_org scoping — profile_other_org belongs to other_org" do
    other_id = ActiveRecord::FixtureSet.identify(:other_org)
    profile  = scan_profiles(:profile_other_org)
    assert_equal other_id, profile.organization_id
  end
end
