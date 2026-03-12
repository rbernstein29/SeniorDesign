require "test_helper"

class SessionsControllerTest < ActionDispatch::IntegrationTest
  test "GET /session/new renders login page" do
    get new_session_path
    assert_response :success
  end

  test "POST /session with valid credentials creates session and redirects" do
    user = users(:admin_user)
    assert_difference "Session.count", 1 do
      post session_path, params: { email_address: user.email_address, password: "password" }
    end
    assert_redirected_to root_path
  end

  test "POST /session with invalid password does not create session" do
    user = users(:admin_user)
    assert_no_difference "Session.count" do
      post session_path, params: { email_address: user.email_address, password: "wrongpassword" }
    end
    assert_response :unprocessable_entity
  end

  test "POST /session with unknown email does not create session" do
    assert_no_difference "Session.count" do
      post session_path, params: { email_address: "nobody@example.com", password: "password" }
    end
    assert_response :unprocessable_entity
  end

  test "DELETE /session destroys session and redirects to login" do
    user = users(:admin_user)
    sign_in_as(user)

    assert_difference "Session.count", -1 do
      delete session_path
    end
    assert_redirected_to new_session_path
  end
end
