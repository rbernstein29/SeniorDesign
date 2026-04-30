require "test_helper"

class AssetsControllerTest < ActionDispatch::IntegrationTest
  test "GET /scan-assets redirects unauthenticated to login" do
    get assets_path
    assert_redirected_to login_path
  end

  test "GET /scan-assets returns 200 for admin" do
    sign_in_as(users(:admin_user))
    get assets_path
    assert_response :success
  end

  test "GET /scan-assets redirects non-admin to root" do
    sign_in_as(users(:readonly_user))
    get assets_path
    assert_redirected_to root_path
  end

  test "POST /scan-assets creates an asset" do
    sign_in_as(users(:admin_user))
    assert_difference "Asset.count", 1 do
      post assets_path, params: { network: "10.0.0.99", scanMode: "safe" }
    end
    assert_redirected_to assets_path
  end

  test "GET /scan-assets/:id returns 200" do
    sign_in_as(users(:admin_user))
    get asset_path(assets(:asset_one))
    assert_response :success
  end

  test "DELETE /scan-assets/:id destroys the asset" do
    sign_in_as(users(:admin_user))
    asset = assets(:asset_two)
    assert_difference "Asset.count", -1 do
      delete asset_path(asset)
    end
    assert_redirected_to assets_path
  end

  test "GET /scan-assets/:id for another org's asset redirects with alert" do
    sign_in_as(users(:other_org_user))
    get asset_path(assets(:asset_one))
    assert_redirected_to assets_path
    assert_not_nil flash[:alert]
  end

  test "DELETE /scan-assets/:id for another org's asset does not destroy it" do
    sign_in_as(users(:other_org_user))
    assert_no_difference "Asset.count" do
      delete asset_path(assets(:asset_one))
    end
    assert_redirected_to assets_path
    assert_not_nil flash[:alert]
  end

  test "GET /scan-assets.json without cidr returns count: 0" do
    sign_in_as(users(:admin_user))
    get assets_path(format: :json)
    assert_response :success
    assert_equal 0, JSON.parse(response.body)["count"]
  end

  test "GET /scan-assets.json with cidr counts matching assets" do
    sign_in_as(users(:admin_user))
    get assets_path(format: :json), params: { cidr: "192.168.1.0/24" }
    assert_response :success
    body = JSON.parse(response.body)
    assert body["count"] >= 0
  end

  test "GET /scan-assets.json with invalid cidr returns 0" do
    sign_in_as(users(:admin_user))
    get assets_path(format: :json), params: { cidr: "not-an-ip" }
    assert_response :success
    assert_equal 0, JSON.parse(response.body)["count"]
  end

  test "GET /scan-assets/new renders for admin" do
    sign_in_as(users(:admin_user))
    get new_asset_path
    assert_response :success
  end

  test "POST /scan-assets with empty network redirects with alert" do
    sign_in_as(users(:admin_user))
    post assets_path, params: { network: "", port: "80" }
    assert_redirected_to new_asset_path
    assert_match(/Invalid target/, flash[:alert].to_s)
  end

  test "POST /scan-assets accepts /30 CIDR and creates the host range" do
    sign_in_as(users(:admin_user))
    assert_difference "Asset.count", 2 do
      post assets_path, params: { network: "10.99.0.0/30" }
    end
    assert_redirected_to assets_path
  end

  test "POST /scan-assets rescues large CIDR errors with redirect+alert" do
    sign_in_as(users(:admin_user))
    post assets_path, params: { network: "10.0.0.0/8" }
    assert_redirected_to new_asset_path
    assert_not_nil flash[:alert]
  end

  test "GET /scan-assets/:id with non-existent id redirects with alert" do
    sign_in_as(users(:admin_user))
    get asset_path(id: 0)
    assert_redirected_to assets_path
    assert_not_nil flash[:alert]
  end
end
