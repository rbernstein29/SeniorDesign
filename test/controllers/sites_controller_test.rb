require "test_helper"

class SitesControllerTest < ActionDispatch::IntegrationTest
  test "GET /sites redirects unauthenticated to login" do
    get sites_path
    assert_redirected_to login_path
  end

  test "GET /sites returns 200 for authenticated user" do
    sign_in_as(users(:admin_user))
    get sites_path
    assert_response :success
  end

  test "POST /sites creates a site" do
    sign_in_as(users(:admin_user))
    assert_difference "Site.count", 1 do
      post sites_path, params: { site: { name: "New Branch", network_range: "10.10.0.0/24" } }
    end
    assert_redirected_to sites_path
  end

  test "POST /sites without a name does not create site" do
    sign_in_as(users(:admin_user))
    assert_no_difference "Site.count" do
      post sites_path, params: { site: { name: "" } }
    end
    assert_redirected_to sites_path
    assert_not_nil flash[:alert]
  end

  test "DELETE /sites/:id destroys the site" do
    sign_in_as(users(:admin_user))
    site = sites(:open_site)
    assert_difference "Site.count", -1 do
      delete site_path(site)
    end
    assert_redirected_to sites_path
  end
end
