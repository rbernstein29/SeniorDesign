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
end
