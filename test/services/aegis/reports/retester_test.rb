require "test_helper"

class Aegis::Reports::RetesterTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  def setup
    @scan = scans(:completed_scan)
    @report = Report.new(
      report_name: "RT",
      organization_id: organizations(:acme).id,
      user: users(:admin_user),
      report_type: "full",
      scan: @scan,
      generated_at: Time.current
    )
  end

  test "queues ScanJob with allowlist and asset_ids when findings exist" do
    result = nil
    assert_enqueued_with(job: ScanJob) do
      result = Aegis::Reports::Retester.new(
        @report,
        organization_id: organizations(:acme).id,
        user_id: users(:admin_user).id
      ).call
    end

    assert result.queued?
    assert_equal 2, result.asset_count
    assert_equal 2, result.module_count

    job = enqueued_jobs.last
    org_id, profile, user_id, asset_ids, opts = job[:args]
    assert_equal organizations(:acme).id, org_id
    assert_kind_of Array, profile["module_allowlist"]
    assert_equal users(:admin_user).id, user_id
    assert_equal Finding.where(scan_id: @scan.id).pluck(:asset_id).uniq.sort, asset_ids.sort
    assert_equal @scan.id, opts["retest_of"]
  end

  test "returns error result when no findings" do
    empty_scan = scans(:running_scan)
    @report.scan = empty_scan

    assert_no_enqueued_jobs do
      result = Aegis::Reports::Retester.new(
        @report,
        organization_id: organizations(:acme).id,
        user_id: users(:admin_user).id
      ).call

      refute result.queued?
      assert_equal "No findings to retest", result.error
    end
  end

  test "Result#queued? aliases queued attribute" do
    result = Aegis::Reports::Retester::Result.new(queued: true)
    assert result.queued?
    assert Aegis::Reports::Retester::Result.new(queued: false).queued? == false
  end
end
