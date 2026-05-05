require "test_helper"

class ReportsControllerTest < ActionDispatch::IntegrationTest

  # ── DELETE /reports/:id ──────────────────────────────────────────────────────

  test "DELETE /reports/:id redirects unauthenticated to login" do
    delete report_path(reports(:report_one))
    assert_redirected_to login_path
  end

  test "DELETE /reports/:id destroys the report" do
    sign_in_as(users(:admin_user))
    assert_difference "Report.count", -1 do
      delete report_path(reports(:report_one))
    end
    assert_redirected_to reports_path
  end

  test "DELETE /reports/:id with non-existent id redirects with alert" do
    sign_in_as(users(:admin_user))
    delete report_path(id: 0)
    assert_redirected_to reports_path
    assert_not_nil flash[:alert]
  end

  # ── GET download_json ────────────────────────────────────────────────────────

  test "GET download_json redirects unauthenticated to login" do
    get download_json_report_path(reports(:report_one))
    assert_redirected_to login_path
  end

  test "GET download_json returns JSON attachment" do
    sign_in_as(users(:admin_user))
    get download_json_report_path(reports(:report_one))
    assert_response :success
    assert_includes response.content_type, "json"
    assert_equal "attachment", response.headers["Content-Disposition"].split(";").first
  end

  test "GET download_json with non-existent id redirects with alert" do
    sign_in_as(users(:admin_user))
    get download_json_report_path(id: 0)
    assert_redirected_to reports_path
    assert_not_nil flash[:alert]
  end

  test "GET download_json for another org report redirects with alert" do
    sign_in_as(users(:other_org_user))
    get download_json_report_path(reports(:report_one))
    assert_redirected_to reports_path
    assert_not_nil flash[:alert]
  end

  # ── GET download_xlsx ────────────────────────────────────────────────────────

  test "GET download_xlsx redirects unauthenticated to login" do
    get download_xlsx_report_path(reports(:report_one))
    assert_redirected_to login_path
  end

  test "GET download_xlsx returns xlsx attachment" do
    sign_in_as(users(:admin_user))
    get download_xlsx_report_path(reports(:report_one))
    assert_response :success
    assert_includes response.content_type, "spreadsheetml"
    assert_equal "attachment", response.headers["Content-Disposition"].split(";").first
  end

  test "GET download_xlsx with non-existent id redirects with alert" do
    sign_in_as(users(:admin_user))
    get download_xlsx_report_path(id: 0)
    assert_redirected_to reports_path
    assert_not_nil flash[:alert]
  end

  # ── GET download_csv ─────────────────────────────────────────────────────────

  test "GET download_csv redirects unauthenticated to login" do
    get download_csv_report_path(reports(:report_one))
    assert_redirected_to login_path
  end

  test "GET download_csv returns csv attachment" do
    sign_in_as(users(:admin_user))
    get download_csv_report_path(reports(:report_one))
    assert_response :success
    assert_includes response.content_type, "text/csv"
    assert_equal "attachment", response.headers["Content-Disposition"].split(";").first
  end

  test "GET download_csv with non-existent id redirects with alert" do
    sign_in_as(users(:admin_user))
    get download_csv_report_path(id: 0)
    assert_redirected_to reports_path
    assert_not_nil flash[:alert]
  end

  # ── GET /reports/:id (show) ──────────────────────────────────────────────────

  test "GET show redirects unauthenticated to login" do
    get report_path(reports(:report_one))
    assert_redirected_to login_path
  end

  test "GET show renders the report" do
    sign_in_as(users(:admin_user))
    NvdEnrichmentService.stub(:enrich, ->(_e) { nil }) do
      get report_path(reports(:report_one))
    end
    assert_response :success
  end

  test "GET show with non-existent id redirects with alert" do
    sign_in_as(users(:admin_user))
    get report_path(id: 0)
    assert_redirected_to reports_path
    assert_not_nil flash[:alert]
  end

  test "GET show triggers prior-scan comparison when previous completed scan exists" do
    sign_in_as(users(:admin_user))
    report = reports(:report_one)

    prev_scan = scans(:completed_scan)
    current_scan = Scan.create!(
      scan_name: "newer",
      organization_id: organizations(:acme).id,
      initiated_by: users(:admin_user).id,
      status: "completed",
      start_time: 30.minutes.ago,
      end_time: 5.minutes.ago,
      safe_mode: prev_scan.safe_mode?
    )
    report.update_columns(scan_id: current_scan.id)

    # recurring finding (matches prev_scan's finding_one)
    Finding.create!(
      scan_id: current_scan.id,
      asset_id: assets(:asset_one).id,
      exploit_id: exploits(:exploit_one).id,
      severity: "critical", status: "open", confidence: "high",
      port: "445", discovered_at: 1.minute.ago
    )
    # new finding (not present on prev_scan): create a brand-new asset
    # to guarantee the (asset_id, exploit_id) pair isn't in prev_pairs
    new_asset = Asset.create!(
      ip_address: "10.77.77.77",
      organization_id: organizations(:acme).id
    )
    Finding.create!(
      scan_id: current_scan.id,
      asset_id: new_asset.id,
      exploit_id: exploits(:exploit_one).id,
      severity: "high", status: "open", confidence: "medium",
      port: "22", discovered_at: 1.minute.ago
    )

    NvdEnrichmentService.stub(:enrich, ->(_e) { nil }) do
      get report_path(report)
    end
    assert_response :success
  end

  # ── POST /reports/:id/retest ────────────────────────────────────────────────

  test "POST retest queues a job and redirects to scans" do
    sign_in_as(users(:admin_user))
    report = reports(:report_one)
    report.update_columns(scan_id: scans(:completed_scan).id)

    assert_enqueued_with(job: ScanJob) do
      post retest_report_path(report)
    end
    assert_redirected_to scans_path
  end

  test "POST retest redirects to report when no findings to retest" do
    sign_in_as(users(:admin_user))
    report = reports(:report_one)
    report.update_columns(scan_id: scans(:running_scan).id)

    post retest_report_path(report)
    assert_redirected_to report_path(report)
    assert_not_nil flash[:alert]
  end

  test "POST retest with non-existent id redirects with alert" do
    sign_in_as(users(:admin_user))
    post retest_report_path(id: 0)
    assert_redirected_to reports_path
    assert_not_nil flash[:alert]
  end

  # ── GET download_whitebox_json ──────────────────────────────────────────────

  test "GET download_whitebox_json rejects non-whitebox report" do
    sign_in_as(users(:admin_user))
    report = reports(:report_one)
    refute report.whitebox?
    get download_whitebox_json_report_path(report)
    assert_redirected_to report_path(report)
    assert_not_nil flash[:alert]
  end

  test "GET download_whitebox_json sends payload for whitebox report" do
    sign_in_as(users(:admin_user))
    report = reports(:report_one)
    report.update_columns(report_type: "whitebox", report_data: [
      { "target" => "1.1.1.1", "isVulnerable" => true }
    ])
    get download_whitebox_json_report_path(report)
    assert_response :success
    assert_includes response.content_type, "json"
  end

  test "GET download_whitebox_json with non-existent id redirects with alert" do
    sign_in_as(users(:admin_user))
    get download_whitebox_json_report_path(id: 0)
    assert_redirected_to reports_path
    assert_not_nil flash[:alert]
  end

  # ── GET data ────────────────────────────────────────────────────────────────

  test "GET data returns report_data JSON" do
    sign_in_as(users(:admin_user))
    get data_report_path(reports(:report_one))
    assert_response :success
    assert JSON.parse(response.body).key?("report_data")
  end

  test "GET data returns 404 JSON when report missing" do
    sign_in_as(users(:admin_user))
    get data_report_path(id: 0)
    assert_response :not_found
    assert_equal "Not found", JSON.parse(response.body)["error"]
  end
end
