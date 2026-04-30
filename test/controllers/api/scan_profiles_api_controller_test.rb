require "test_helper"

class Api::ScanProfilesApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = users(:admin_user).api_key
    @readonly_key = users(:readonly_user).api_key
  end

  test "GET /api/:key/scan-profiles returns list for admin" do
    get "/api/#{@admin_key}/scan-profiles"
    assert_response :success
    json = JSON.parse(response.body)
    assert_kind_of Array, json["scan_profiles"]
  end

  test "GET /api/:key/scan-profiles returns 403 for readonly user" do
    get "/api/#{@readonly_key}/scan-profiles"
    assert_response :forbidden
  end

  test "POST /api/:key/scan-profiles creates a profile" do
    assert_difference "ScanProfile.count", 1 do
      post "/api/#{@admin_key}/scan-profiles",
           params: { name: "New Profile", description: "test", safe_mode: "false" }
    end
    assert_response :created
    json = JSON.parse(response.body)
    assert_equal "New Profile", json["scan_profile"]["name"]
    assert_equal false,         json["scan_profile"]["safe_mode"]
  end

  test "POST /api/:key/scan-profiles creates safe mode profile" do
    post "/api/#{@admin_key}/scan-profiles",
         params: { name: "Recon Only", safe_mode: "true" }
    assert_response :created
    json = JSON.parse(response.body)
    assert_equal true, json["scan_profile"]["safe_mode"]
  end

  test "POST /api/:key/scan-profiles returns 403 for readonly user" do
    post "/api/#{@readonly_key}/scan-profiles", params: { name: "Blocked" }
    assert_response :forbidden
  end

  test "DELETE /api/:key/scan-profiles/:id deletes profile" do
    profile = scan_profiles(:profile_one)
    assert_difference "ScanProfile.count", -1 do
      delete "/api/#{@admin_key}/scan-profiles/#{profile.id}"
    end
    assert_response :success
  end

  test "DELETE /api/:key/scan-profiles/:id returns 404 for missing profile" do
    delete "/api/#{@admin_key}/scan-profiles/0"
    assert_response :not_found
  end

  test "GET /api/:key/scan-profiles with invalid key returns 401" do
    get "/api/bad_key/scan-profiles"
    assert_response :unauthorized
  end

  test "POST /api/:key/scan-profiles preserves exploit_ids" do
    post "/api/#{@admin_key}/scan-profiles",
         params: { name: "API Picky", exploit_ids: [exploits(:exploit_one).id] }
    assert_response :created
    profile = ScanProfile.order(:id).last
    assert_equal [exploits(:exploit_one).id], profile.exploit_ids
  end

  test "POST /api/:key/scan-profiles returns 422 with invalid params" do
    post "/api/#{@admin_key}/scan-profiles", params: { name: "" }
    assert_response :unprocessable_entity
    assert JSON.parse(response.body)["error"].present?
  end
end
