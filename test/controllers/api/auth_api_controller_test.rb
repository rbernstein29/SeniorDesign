require "test_helper"

class Api::AuthApiControllerTest < ActionDispatch::IntegrationTest
  test "POST /api/auth returns api_key on valid credentials" do
    post "/api/auth", params: {
      email_address: "admin@example.com",
      password: TEST_FIXTURE_PASSWORD
    }
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal users(:admin_user).api_key, json["api_key"]
    assert_equal "admin@example.com", json["email"]
    assert_equal "admin", json["access_level"]
    assert_equal users(:admin_user).name, json["name"]
  end

  test "POST /api/auth uppercases email and trims whitespace" do
    post "/api/auth", params: {
      email_address: "  ADMIN@example.com  ",
      password: TEST_FIXTURE_PASSWORD
    }
    assert_response :success
  end

  test "POST /api/auth generates api_key when user has none" do
    user = users(:other_org_user)
    assert_nil user.api_key

    post "/api/auth", params: {
      email_address: user.email_address,
      password: TEST_FIXTURE_PASSWORD
    }
    assert_response :success
    json = JSON.parse(response.body)
    assert_present_key = json["api_key"]
    assert assert_present_key.present?
    assert_equal assert_present_key, user.reload.api_key
  end

  test "POST /api/auth without email returns 400" do
    post "/api/auth", params: { password: TEST_FIXTURE_PASSWORD }
    assert_response :bad_request
    assert_equal "email_address and password are required", JSON.parse(response.body)["error"]
  end

  test "POST /api/auth without password returns 400" do
    post "/api/auth", params: { email_address: "admin@example.com" }
    assert_response :bad_request
  end

  test "POST /api/auth with bad password returns 401" do
    post "/api/auth", params: {
      email_address: "admin@example.com",
      password: "wrong-password"
    }
    assert_response :unauthorized
    assert_equal "Invalid email or password", JSON.parse(response.body)["error"]
  end

  test "POST /api/auth with unverified email returns 403" do
    user = users(:admin_user)
    user.update_column(:email_verified_at, nil)

    post "/api/auth", params: {
      email_address: user.email_address,
      password: TEST_FIXTURE_PASSWORD
    }
    assert_response :forbidden
    assert_equal "Email address not verified", JSON.parse(response.body)["error"]
  end
end
