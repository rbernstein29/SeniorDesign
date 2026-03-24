require "test_helper"

class ScanTest < ActiveSupport::TestCase
  test "for_org scope filters by organization" do
    acme_id = ActiveRecord::FixtureSet.identify(:acme)
    acme_scans = Scan.for_org(acme_id)
    assert acme_scans.all? { |s| s.organization_id == acme_id }
  end

  test "running scope returns only running scans" do
    running = Scan.running
    assert running.all? { |s| s.status == "running" }
    assert_includes running, scans(:running_scan)
  end

  test "completed scope returns only completed scans" do
    completed = Scan.completed
    assert completed.all? { |s| s.status == "completed" }
    assert_includes completed, scans(:completed_scan)
  end

  test "failed scope returns failed and cancelled scans" do
    failed = Scan.failed
    assert failed.all? { |s| %w[failed cancelled].include?(s.status) }
    assert_includes failed, scans(:failed_scan)
  end
end
