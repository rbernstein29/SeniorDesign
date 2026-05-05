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

  test "perform invokes progress callback to broadcast updates" do
    captured_pct = nil
    ScanService.stub(:new, ->(*args, **kwargs, &blk) {
      obj = Object.new
      obj.define_singleton_method(:perform) { blk.call(1, 2, "1.2.3.4") if blk }
      obj
    }) do
      Turbo::StreamsChannel.stub(:broadcast_update_to, ->(stream, **opts) {
        captured_pct ||= opts[:html].to_s[/width: (\d+)%/, 1]&.to_i
      }) do
        ScanJob.new.perform(@org.id, {}, @user.id, [@asset.id])
      end
    end
    assert captured_pct, "progress callback should drive a broadcast_update_to call"
  end

  test "perform falls back to active asset count when asset_ids empty" do
    ScanService.stub(:new, ->(*args, **kwargs, &blk) {
      obj = Object.new
      obj.define_singleton_method(:perform) {}
      obj
    }) do
      Turbo::StreamsChannel.stub(:broadcast_update_to, nil) do
        assert_difference "Scan.count", 1 do
          ScanJob.new.perform(@org.id, {}, @user.id, [])
        end
      end
    end
    new_scan = Scan.order(created_at: :desc).first
    expected_total = Asset.where(organization_id: @org.id, is_active: true).count
    assert_equal expected_total, new_scan.total_assets
  end

  test "perform retest auto-remediates findings from prior scan when current results are clean" do
    original = scans(:completed_scan)
    finding  = findings(:finding_one)
    finding.update!(status: "open")

    ScanService.stub(:new, ->(*args, **kwargs, &blk) {
      obj = Object.new
      obj.define_singleton_method(:perform) do
        new_scan = Scan.order(created_at: :desc).first
        ScanExploit.create!(
          scan_id:    new_scan.id,
          asset_id:   finding.asset_id,
          exploit_id: finding.exploit_id,
          result:     "not_detected"
        )
      end
      obj
    }) do
      Turbo::StreamsChannel.stub(:broadcast_update_to, nil) do
        ScanJob.new.perform(@org.id, {}, @user.id, [finding.asset_id], { retest_of: original.id })
      end
    end

    finding.reload
    assert_equal "remediated", finding.status
  end

  test "perform enqueues NvdEnrichmentJob for findings with unenriched CVE exploits" do
    exploit   = exploits(:exploit_one)
    asset_id  = assets(:asset_one).id
    exploit_id = exploit.id
    exploit.update_columns(cvss_score: nil) # exploit_one already has cve_id

    ScanService.stub(:new, ->(*args, **kwargs, &blk) {
      obj = Object.new
      obj.define_singleton_method(:perform) do
        new_scan = Scan.order(created_at: :desc).first
        Finding.create!(
          scan_id: new_scan.id, asset_id: asset_id,
          exploit_id: exploit_id, severity: "high", status: "open",
          confidence: "medium", port: "22", discovered_at: Time.current
        )
      end
      obj
    }) do
      Turbo::StreamsChannel.stub(:broadcast_update_to, nil) do
        assert_enqueued_with(job: NvdEnrichmentJob) do
          ScanJob.new.perform(@org.id, {}, @user.id, [@asset.id])
        end
      end
    end
  end

  test "broadcast_progress rescues Turbo errors so the job continues" do
    Turbo::StreamsChannel.stub(:broadcast_update_to, ->(*) { raise "no streams" }) do
      ScanService.stub(:new, ->(*args, **kwargs, &blk) {
        obj = Object.new
        obj.define_singleton_method(:perform) {}
        obj
      }) do
        assert_nothing_raised do
          ScanJob.new.perform(@org.id, {}, @user.id, [@asset.id])
        end
      end
    end
  end
end
