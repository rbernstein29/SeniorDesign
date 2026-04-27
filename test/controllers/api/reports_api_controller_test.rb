require "test_helper"

class Api::ReportsApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = "test_api_key_admin_abc123xyz"
    @readonly_key = "test_api_key_readonly_xyz789"
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
end
