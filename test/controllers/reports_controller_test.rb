require "test_helper"

class ReportsControllerTest < ActionDispatch::IntegrationTest
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
end
