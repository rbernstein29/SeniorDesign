require "test_helper"

class ScanJobTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  def setup
    @org  = organizations(:acme)
    @user = users(:admin_user)
    @asset = assets(:asset_one)
  end

  # ── enqueue ───────────────────────────────────────────────────────────────────

  test "ScanJob is queued to the default queue" do
    assert_equal "default", ScanJob.queue_name
  end

  test "perform_later enqueues a job" do
    assert_enqueued_with(job: ScanJob) do
      ScanJob.perform_later(@org.id, {}, @user.id, [@asset.id])
    end
  end

  # ── perform ───────────────────────────────────────────────────────────────────

  test "perform creates a Scan record" do
    scan_service_stub = ->(org_id, filter_params, user_id, scan, asset_ids, opts, &blk) { }
    ScanService.stub(:new, ->(*args, **kwargs, &blk) {
      obj = Object.new
      obj.define_singleton_method(:perform) {}
      obj
    }) do
      Turbo::StreamsChannel.stub(:broadcast_update_to, nil) do
        assert_difference "Scan.count", 1 do
          ScanJob.new.perform(@org.id, {}, @user.id, [@asset.id])
        end
      end
    end
  end

  test "perform returns early when user is not found" do
    Turbo::StreamsChannel.stub(:broadcast_update_to, nil) do
      assert_no_difference "Scan.count" do
        ScanJob.new.perform(@org.id, {}, -999)
      end
    end
  end

  test "perform creates a retest scan when retest_of is provided" do
    completed = scans(:completed_scan)
    ScanService.stub(:new, ->(*args, **kwargs, &blk) {
      obj = Object.new
      obj.define_singleton_method(:perform) {}
      obj
    }) do
      Turbo::StreamsChannel.stub(:broadcast_update_to, nil) do
        assert_difference "Scan.count", 1 do
          ScanJob.new.perform(@org.id, {}, @user.id, [@asset.id], { retest_of: completed.id })
        end
        new_scan = Scan.order(created_at: :desc).first
        assert new_scan.is_retest
        assert_equal completed.id, new_scan.retest_of
        assert new_scan.scan_name.start_with?("Retest")
      end
    end
  end

  test "perform marks scan failed and re-raises on error" do
    ScanService.stub(:new, ->(*args, **kwargs, &blk) {
      obj = Object.new
      obj.define_singleton_method(:perform) { raise "boom" }
      obj
    }) do
      Turbo::StreamsChannel.stub(:broadcast_update_to, nil) do
        assert_raises(RuntimeError, "boom") do
          ScanJob.new.perform(@org.id, {}, @user.id, [@asset.id])
        end
        failed_scan = Scan.order(created_at: :desc).first
        assert_equal "failed", failed_scan.status
      end
    end
  end
end
