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
end
