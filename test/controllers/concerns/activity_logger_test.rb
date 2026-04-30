require "test_helper"

class ActivityLoggerTest < ActionDispatch::IntegrationTest
  test "log_activity rescues ActivityLog.create! failures so the request succeeds" do
    sign_in_as(users(:admin_user))
    ActivityLog.stub(:create!, ->(*) { raise "db gone" }) do
      assert_difference "Asset.count", 1 do
        post assets_path, params: { network: "10.123.45.67" }
      end
    end
    assert_redirected_to assets_path
  end
end
