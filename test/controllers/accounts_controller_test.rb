require "test_helper"

class AccountsControllerTest < ActionDispatch::IntegrationTest
  test "POST /accounts creates organization and admin user" do
    assert_difference ["Organization.count", "User.count"], 1 do
      post accounts_path, params: {
        organization: { org_name: "Brand New Org" },
        user: { name: "Founder", email_address: "founder@brandnew.com", password: "password", password_confirmation: "password" }
      }
    end
    assert_redirected_to verify_pending_path
  end

  test "POST /accounts with duplicate org_name redirects with alert" do
    assert_no_difference "Organization.count" do
      post accounts_path, params: {
        organization: { org_name: "Acme Corp" },
        user: { name: "Dup", email_address: "dup@acme.com", password: "password", password_confirmation: "password" }
      }
    end
    assert_redirected_to login_path
    assert_not_nil flash[:alert]
  end

  test "PATCH /accounts/generate_api_key requires authentication" do
    patch generate_api_key_path
    assert_redirected_to login_path
  end

  test "PATCH /accounts/generate_api_key creates an API key for current user" do
    user = users(:admin_user)
    user.update_column(:api_key, nil)
    sign_in_as(user)

    patch generate_api_key_path
    user.reload
    assert_not_nil user.api_key
  end
end
