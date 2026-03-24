require "test_helper"

class ReadOnlyAccountsControllerTest < ActionDispatch::IntegrationTest

  test "POST /read_only_accounts redirects unauthenticated to login" do
    post read_only_accounts_path, params: {
      user: { name: "Test RO", email_address: "testro@example.com",
               password: "password", password_confirmation: "password" }
    }
    assert_redirected_to login_path
  end

  test "POST /read_only_accounts creates a readonly user" do
    sign_in_as(users(:admin_user))
    assert_difference "User.count", 1 do
      post read_only_accounts_path, params: {
        user: { name: "New RO User", email_address: "newro@example.com",
                 password: "password", password_confirmation: "password" }
      }
    end
    new_user = User.find_by(email_address: "newro@example.com")
    assert_equal "read_only", new_user.access_level
    assert_equal users(:admin_user).organization_id, new_user.organization_id
  end

  test "DELETE /read_only_accounts/:id destroys the user" do
    sign_in_as(users(:admin_user))
    assert_difference "User.count", -1 do
      delete delete_read_only_account_path(users(:readonly_user))
    end
    assert_redirected_to read_only_accounts_path
  end

  test "DELETE /read_only_accounts/:id cannot delete user from another org" do
    sign_in_as(users(:other_org_user))
    assert_no_difference "User.count" do
      delete delete_read_only_account_path(users(:readonly_user))
    end
    assert_redirected_to read_only_accounts_path
    assert_not_nil flash[:alert]
  end

  test "DELETE /read_only_accounts/:id with nonexistent id redirects with alert" do
    sign_in_as(users(:admin_user))
    delete delete_read_only_account_path(id: 0)
    assert_redirected_to read_only_accounts_path
    assert_not_nil flash[:alert]
  end
end
