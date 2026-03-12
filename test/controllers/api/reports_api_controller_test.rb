require "test_helper"

class Api::ReportsApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @user = users(:admin_user)
    @api_key = "test_api_key_admin_abc123xyz"
  end

  test "GET /api/:api_key/reports returns JSON list" do
    get api_reports_path(api_key: @api_key)
    assert_response :success
    json = JSON.parse(response.body)
    assert_kind_of Array, json
  end

  test "GET /api/:api_key/reports with invalid key returns 401" do
    get api_reports_path(api_key: "invalid_key_xyz")
    assert_response :unauthorized
    json = JSON.parse(response.body)
    assert_equal "Invalid API key", json["error"]
  end

  test "GET /api/:api_key/reports/:id returns single report" do
    report = reports(:report_one)
    get api_report_path(api_key: @api_key, id: report.id)
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal report.id, json["id"]
  end

  test "GET /api/:api_key/reports/:id with wrong id returns 404" do
    get api_report_path(api_key: @api_key, id: 0)
    assert_response :not_found
    json = JSON.parse(response.body)
    assert_equal "Report not found", json["error"]
  end
end
