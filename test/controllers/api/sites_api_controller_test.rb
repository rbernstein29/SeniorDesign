require "test_helper"

class Api::SitesApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = users(:admin_user).api_key
    @readonly_key = users(:readonly_user).api_key
  end

  test "GET /api/:key/sites returns list" do
    get "/api/#{@admin_key}/sites"
    assert_response :success
    json = JSON.parse(response.body)
    assert_kind_of Array, json["sites"]
  end

  test "GET /api/:key/sites returns list for readonly user" do
    get "/api/#{@readonly_key}/sites"
    assert_response :success
  end

  test "POST /api/:key/sites creates a site" do
    assert_difference "Site.count", 1 do
      post "/api/#{@admin_key}/sites", params: { name: "API Test Site", network_range: "10.99.0.0/24" }
    end
    assert_response :created
    json = JSON.parse(response.body)
    assert_equal "API Test Site", json["site"]["name"]
  end

  test "POST /api/:key/sites returns 403 for readonly user" do
    post "/api/#{@readonly_key}/sites", params: { name: "Blocked Site" }
    assert_response :forbidden
  end

  test "DELETE /api/:key/sites/:id deletes site" do
    site = sites(:open_site)
    assert_difference "Site.count", -1 do
      delete "/api/#{@admin_key}/sites/#{site.id}"
    end
    assert_response :success
  end

  test "DELETE /api/:key/sites/:id returns 404 for missing site" do
    delete "/api/#{@admin_key}/sites/0"
    assert_response :not_found
  end

  test "GET /api/:key/sites with invalid key returns 401" do
    get "/api/bad_key/sites"
    assert_response :unauthorized
  end

  test "POST /api/:key/sites surfaces RecordInvalid as 422" do
    Site.stub(:create!, ->(*) { raise ActiveRecord::RecordInvalid.new(Site.new) }) do
      post "/api/#{@admin_key}/sites", params: { name: "" }
    end
    assert_response :unprocessable_entity
    assert JSON.parse(response.body)["error"].present?
  end
end
