require "test_helper"

class Api::ReportsApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = users(:admin_user).api_key
    @readonly_key = users(:readonly_user).api_key
  end

  test "GET /api/:key/reports returns JSON list" do
    get "/api/#{@admin_key}/reports"
    assert_response :success
    json = JSON.parse(response.body)
    assert_kind_of Array, json["reports"]
  end

  test "GET /api/:key/reports returns list for readonly user" do
    get "/api/#{@readonly_key}/reports"
    assert_response :success
  end

  test "GET /api/:key/reports with invalid key returns 401" do
    get "/api/invalid_key_xyz/reports"
    assert_response :unauthorized
    json = JSON.parse(response.body)
    assert_equal "Invalid API key", json["error"]
  end

  test "GET /api/:key/reports/:id returns single report" do
    report = reports(:report_one)
    get "/api/#{@admin_key}/reports/#{report.id}"
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal report.id, json["report"]["id"]
  end

  test "GET /api/:key/reports/:id with wrong id returns 404" do
    get "/api/#{@admin_key}/reports/0"
    assert_response :not_found
    json = JSON.parse(response.body)
    assert_equal "Report not found", json["error"]
  end

  test "GET /api/:key/reports/:id/data returns report_data" do
    report = reports(:report_one)
    get "/api/#{@admin_key}/reports/#{report.id}/data"
    assert_response :success
    json = JSON.parse(response.body)
    assert json.key?("report_data")
  end

  test "GET /api/:key/reports/:id/download_json sends file attachment" do
    report = reports(:report_one)
    get "/api/#{@admin_key}/reports/#{report.id}/download_json"
    assert_response :success
    assert_equal "application/json", response.content_type
    assert_includes response.headers["Content-Disposition"], "attachment"
  end

  test "GET /api/:key/reports/:id/download_csv sends file attachment" do
    report = reports(:report_one)
    get "/api/#{@admin_key}/reports/#{report.id}/download_csv"
    assert_response :success
    assert_equal "text/csv", response.content_type
    assert_includes response.headers["Content-Disposition"], "attachment"
  end

  test "GET /api/:key/reports/:id/download_xlsx sends file attachment" do
    report = reports(:report_one)
    get "/api/#{@admin_key}/reports/#{report.id}/download_xlsx"
    assert_response :success
    assert_includes response.headers["Content-Disposition"], "attachment"
  end

  test "DELETE /api/:key/reports/:id deletes report" do
    report = reports(:report_two)
    assert_difference "Report.count", -1 do
      delete "/api/#{@admin_key}/reports/#{report.id}"
    end
    assert_response :success
    json = JSON.parse(response.body)
    assert json["deleted"]
  end

  test "DELETE /api/:key/reports/:id returns 404 for missing report" do
    delete "/api/#{@admin_key}/reports/0"
    assert_response :not_found
  end

  test "POST /api/:key/reports/:id/retest returns 403 for readonly user" do
    report = reports(:report_one)
    post "/api/#{@readonly_key}/reports/#{report.id}/retest"
    assert_response :forbidden
  end

  test "GET download_json 404 for non-existent report" do
    get "/api/#{@admin_key}/reports/0/download_json"
    assert_response :not_found
    assert_equal "Report not found", JSON.parse(response.body)["error"]
  end

  test "GET download_xlsx 404 for non-existent report" do
    get "/api/#{@admin_key}/reports/0/download_xlsx"
    assert_response :not_found
  end

  test "GET download_csv 404 for non-existent report" do
    get "/api/#{@admin_key}/reports/0/download_csv"
    assert_response :not_found
  end

  test "GET download_whitebox_json rejects non-whitebox report" do
    report = reports(:report_one)
    get "/api/#{@admin_key}/reports/#{report.id}/download_whitebox_json"
    assert_response :unprocessable_entity
    assert_equal "Not a whitebox report", JSON.parse(response.body)["error"]
  end

  test "GET download_whitebox_json returns payload for whitebox report" do
    report = reports(:report_one)
    report.update_columns(report_type: "whitebox", report_data: [{ "isVulnerable" => true }])
    get "/api/#{@admin_key}/reports/#{report.id}/download_whitebox_json"
    assert_response :success
    assert_includes response.headers["Content-Disposition"], "attachment"
  end

  test "GET download_whitebox_json 404 for non-existent report" do
    get "/api/#{@admin_key}/reports/0/download_whitebox_json"
    assert_response :not_found
  end

  test "GET data 404 for non-existent report" do
    get "/api/#{@admin_key}/reports/0/data"
    assert_response :not_found
  end

  test "POST retest queues a job for admin and returns asset/module counts" do
    report = reports(:report_one)
    report.update_columns(scan_id: scans(:completed_scan).id)
    assert_enqueued_with(job: ScanJob) do
      post "/api/#{@admin_key}/reports/#{report.id}/retest"
    end
    assert_response :accepted
    body = JSON.parse(response.body)
    assert body["queued"]
    assert body["asset_count"] >= 1
    assert body["module_count"] >= 1
  end

  test "POST retest returns 422 when no findings to retest" do
    report = reports(:report_one)
    report.update_columns(scan_id: scans(:running_scan).id)
    post "/api/#{@admin_key}/reports/#{report.id}/retest"
    assert_response :unprocessable_entity
    assert_equal "No findings to retest", JSON.parse(response.body)["error"]
  end

  test "POST retest 404 for non-existent report" do
    post "/api/#{@admin_key}/reports/0/retest"
    assert_response :not_found
  end
end
