require "test_helper"

class Api::AssetsApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = users(:admin_user).api_key
    @readonly_key = users(:readonly_user).api_key
  end

  test "GET /api/:key/assets returns list for admin" do
    get "/api/#{@admin_key}/assets"
    assert_response :success
    json = JSON.parse(response.body)
    assert_kind_of Array, json["assets"]
  end

  test "GET /api/:key/assets returns list for readonly user" do
    get "/api/#{@readonly_key}/assets"
    assert_response :success
  end

  test "GET /api/:key/assets with cidr returns count" do
    get "/api/#{@admin_key}/assets?cidr=192.168.1.0/24"
    assert_response :success
    json = JSON.parse(response.body)
    assert json["count"] >= 0
  end

  test "GET /api/:key/assets/:id returns asset detail" do
    asset = assets(:asset_one)
    get "/api/#{@admin_key}/assets/#{asset.id}"
    assert_response :success
    json = JSON.parse(response.body)
    assert_equal asset.id, json["asset"]["id"]
  end

  test "GET /api/:key/assets/:id returns 404 for missing asset" do
    get "/api/#{@admin_key}/assets/0"
    assert_response :not_found
  end

  test "POST /api/:key/assets creates a single IP asset" do
    assert_difference "Asset.count", 1 do
      post "/api/#{@admin_key}/assets", params: { network: "10.1.2.3" }
    end
    assert_response :created
    json = JSON.parse(response.body)
    assert_equal 1, json["created"]
  end

  test "POST /api/:key/assets returns 403 for readonly user" do
    post "/api/#{@readonly_key}/assets", params: { network: "10.1.2.4" }
    assert_response :forbidden
  end

  test "POST /api/:key/assets returns 422 for invalid target" do
    post "/api/#{@admin_key}/assets", params: { network: "not-an-ip" }
    assert_response :unprocessable_entity
  end

  test "DELETE /api/:key/assets/:id deletes asset" do
    asset = assets(:asset_one)
    assert_difference "Asset.count", -1 do
      delete "/api/#{@admin_key}/assets/#{asset.id}"
    end
    assert_response :success
    json = JSON.parse(response.body)
    assert json["deleted"]
  end

  test "DELETE /api/:key/assets/:id returns 403 for readonly user" do
    asset = assets(:asset_two)
    delete "/api/#{@readonly_key}/assets/#{asset.id}"
    assert_response :forbidden
  end

  test "DELETE /api/:key/assets/:id returns 404 for missing asset" do
    delete "/api/#{@admin_key}/assets/0"
    assert_response :not_found
  end

  test "GET /api/:key/assets with invalid key returns 401" do
    get "/api/bad_key/assets"
    assert_response :unauthorized
  end

  test "GET /api/:key/assets with invalid cidr returns 422" do
    get "/api/#{@admin_key}/assets", params: { cidr: "not-a-cidr" }
    assert_response :unprocessable_entity
    assert_equal "Invalid CIDR", JSON.parse(response.body)["error"]
  end

  test "POST /api/:key/assets surfaces creation errors with 422" do
    Asset.stub(:create!, ->(*) { raise "kaboom" }) do
      post "/api/#{@admin_key}/assets", params: { network: "10.99.99.1" }
    end
    assert_response :unprocessable_entity
    assert_match(/kaboom/, JSON.parse(response.body)["error"])
  end

  test "POST /api/:key/assets with /30 CIDR creates the host range" do
    assert_difference "Asset.count", 2 do
      post "/api/#{@admin_key}/assets", params: { network: "10.55.0.0/30" }
    end
    assert_response :created
  end

  test "POST /api/:key/assets rejects oversized CIDR with 422" do
    post "/api/#{@admin_key}/assets", params: { network: "10.0.0.0/8" }
    assert_response :unprocessable_entity
    assert_match(/Range too large/, JSON.parse(response.body)["error"])
  end
end
