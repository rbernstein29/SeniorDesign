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
end
