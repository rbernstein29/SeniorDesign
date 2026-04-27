require "test_helper"

class Api::AccountApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = users(:admin_user).api_key
    @readonly_key = users(:readonly_user).api_key
  end

  test "GET /api/:key/account returns account info for admin" do
    get "/api/#{@admin_key}/account"
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "admin@example.com", json["account"]["email"]
    assert_equal "admin",             json["account"]["access_level"]
    assert_equal "Acme Corp",         json["account"]["organization"]["name"]
  end

  test "GET /api/:key/account returns account info for readonly user" do
    get "/api/#{@readonly_key}/account"
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal "readonly@example.com", json["account"]["email"]
    assert_equal "read_only",            json["account"]["access_level"]
  end

  test "GET /api/:key/account with invalid key returns 401" do
    get "/api/bad_key/account"
    assert_response :unauthorized
  end
end
