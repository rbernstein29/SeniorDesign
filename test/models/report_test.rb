require "test_helper"

class ReportTest < ActiveSupport::TestCase
  test "belongs to user" do
    report = reports(:report_one)
    assert_instance_of User, report.user
  end

  test "scan association is optional" do
    report = Report.new(
      report_name: "No Scan Report",
      organization_id: ActiveRecord::FixtureSet.identify(:acme),
      user_id: ActiveRecord::FixtureSet.identify(:admin_user),
      report_type: "summary",
      generated_at: Time.current
    )
    assert report.valid?
  end

  # ── whitebox? ────────────────────────────────────────────────────────────────

  test "whitebox? returns true when report_type is whitebox" do
    report = reports(:report_one)
    report.report_type = "whitebox"
    assert report.whitebox?
  end

  test "whitebox? returns false for non-whitebox types" do
    report = reports(:report_one)
    report.report_type = "reconnaissance"
    assert_not report.whitebox?
  end

  # ── safe_mode? ───────────────────────────────────────────────────────────────

  test "safe_mode? returns true when report_type is reconnaissance" do
    report = reports(:report_one)
    report.report_type = "reconnaissance"
    assert report.safe_mode?
  end

  test "safe_mode? returns false for other types" do
    report = reports(:report_one)
    report.report_type = "whitebox"
    assert_not report.safe_mode?
  end

  # ── display_type ─────────────────────────────────────────────────────────────

  test "display_type returns Safe Mode for reconnaissance" do
    report = reports(:report_one)
    report.report_type = "reconnaissance"
    assert_equal "Safe Mode", report.display_type
  end

  test "display_type returns Whitebox for whitebox" do
    report = reports(:report_one)
    report.report_type = "whitebox"
    assert_equal "Whitebox", report.display_type
  end

  test "display_type returns Exploit for any other type" do
    report = reports(:report_one)
    report.report_type = "summary"
    assert_equal "Exploit", report.display_type
  end
end
