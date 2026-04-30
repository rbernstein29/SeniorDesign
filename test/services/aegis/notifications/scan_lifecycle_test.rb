require "test_helper"

class Aegis::Notifications::ScanLifecycleTest < ActiveSupport::TestCase
  L = Aegis::Notifications::ScanLifecycle

  def org
    organizations(:acme)
  end

  def user
    users(:admin_user)
  end

  test "started logs cyan activity with target count" do
    scan = scans(:running_scan)
    assert_difference "ActivityLog.count", 1 do
      L.started(scan, 5, organization_id: org.id, user_id: user.id)
    end
    log = ActivityLog.order(:id).last
    assert_equal "cyan", log.color
    assert_match(/started on 5 target/, log.text)
  end

  test "completed logs green activity with finding count" do
    scan = scans(:completed_scan)
    assert_difference "ActivityLog.count", 1 do
      L.completed(scan, 3, organization_id: org.id, user_id: user.id)
    end
    log = ActivityLog.order(:id).last
    assert_equal "green", log.color
    assert_match(/completed — 3 finding/, log.text)
  end

  test "failed logs red activity, including message when provided" do
    scan = scans(:failed_scan)
    assert_difference "ActivityLog.count", 1 do
      L.failed(scan, organization_id: org.id, user_id: user.id, message: "boom")
    end
    log = ActivityLog.order(:id).last
    assert_equal "red", log.color
    assert_match(/boom/, log.text)
  end

  test "failed logs without message when none supplied" do
    scan = scans(:failed_scan)
    L.failed(scan, organization_id: org.id, user_id: user.id)
    assert_no_match(/:/, ActivityLog.order(:id).last.text.split("</strong>").last)
  end

  test "failed handles nil scan with generic name" do
    L.failed(nil, organization_id: org.id, user_id: user.id, message: "x")
    log = ActivityLog.order(:id).last
    assert_match(/scan/, log.text)
  end

  test "log swallows ActivityLog.create! failures" do
    ActivityLog.stub(:create!, ->(*) { raise "db gone" }) do
      assert_nil L.log(organization_id: org.id, user_id: user.id, color: "red", text: "x")
    end
  end
end
