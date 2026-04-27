require "test_helper"

class ScanProfilesControllerTest < ActionDispatch::IntegrationTest

  test "GET /scan_profiles redirects unauthenticated to login" do
    get scan_profiles_path
    assert_redirected_to login_path
  end

  test "GET /scan_profiles returns 200 for admin" do
    sign_in_as(users(:admin_user))
    get scan_profiles_path
    assert_response :success
  end

  test "GET /scan_profiles redirects readonly user to root" do
    sign_in_as(users(:readonly_user))
    get scan_profiles_path
    assert_redirected_to root_path
  end

  test "POST /scan_profiles creates a profile" do
    sign_in_as(users(:admin_user))
    assert_difference "ScanProfile.count", 1 do
      post scan_profiles_path, params: { name: "Web Exploits", description: "HTTP exploits", safe_mode: "false" }
    end
    assert_redirected_to scan_profiles_path
  end

  test "POST /scan_profiles redirects readonly user to root" do
    sign_in_as(users(:readonly_user))
    post scan_profiles_path, params: { name: "Blocked", safe_mode: "false" }
    assert_redirected_to root_path
  end

  test "DELETE /scan_profiles/:id deletes profile" do
    sign_in_as(users(:admin_user))
    profile = scan_profiles(:profile_one)
    assert_difference "ScanProfile.count", -1 do
      delete scan_profile_path(profile)
    end
    assert_redirected_to scan_profiles_path
  end

  test "DELETE /scan_profiles/:id cannot delete profile from another org" do
    sign_in_as(users(:admin_user))
    other_profile = scan_profiles(:profile_other_org)
    assert_no_difference "ScanProfile.count" do
      delete scan_profile_path(other_profile)
    end
  end
end
