require "test_helper"

class PasswordsControllerTest < ActionDispatch::IntegrationTest

  # ── GET /passwords/new ────────────────────────────────────────────────────────

  test "GET /passwords/new renders without authentication" do
    get new_password_path
    assert_response :success
  end

  # ── POST /passwords (request reset) ──────────────────────────────────────────

  test "POST /passwords with registered email sends reset email" do
    assert_emails 1 do
      post passwords_path, params: { email_address: users(:admin_user).email_address }
    end
    assert_redirected_to new_password_path
    assert_not_nil flash[:notice]
  end

  test "POST /passwords with unknown email shows same notice without sending email" do
    assert_emails 0 do
      post passwords_path, params: { email_address: "nobody@nowhere.com" }
    end
    assert_redirected_to new_password_path
    assert_not_nil flash[:notice]
  end

  test "POST /passwords notice message is identical for known and unknown emails" do
    post passwords_path, params: { email_address: users(:admin_user).email_address }
    notice_known = flash[:notice]

    post passwords_path, params: { email_address: "unknown@nobody.com" }
    notice_unknown = flash[:notice]

    assert_equal notice_known, notice_unknown
  end

  # ── GET /passwords/:token (edit form) ─────────────────────────────────────────

  test "GET /passwords/:token with valid token renders edit form" do
    token = users(:admin_user).password_reset_token
    get edit_password_path(token)
    assert_response :success
  end

  test "GET /passwords/:token with invalid token redirects with alert" do
    get edit_password_path("bad_token_value")
    assert_redirected_to new_password_path
    assert_not_nil flash[:alert]
  end

  test "GET /passwords/:token with expired token redirects with alert" do
    token = users(:admin_user).password_reset_token
    travel_to 16.minutes.from_now do
      get edit_password_path(token)
    end
    assert_redirected_to new_password_path
    assert_not_nil flash[:alert]
  end

  # ── PATCH /passwords/:token (update password) ─────────────────────────────────

  test "PATCH /passwords/:token with matching passwords updates and redirects to login" do
    user  = users(:admin_user)
    token = user.password_reset_token
    new_pw = "NewSecure!Pass2026"

    patch password_path(token), params: { password: new_pw, password_confirmation: new_pw }
    assert_redirected_to new_session_path
    assert_not_nil flash[:notice]

    user.reload
    assert user.authenticate(new_pw)
  end

  test "PATCH /passwords/:token with mismatched passwords redirects back with alert" do
    token = users(:admin_user).password_reset_token
    patch password_path(token), params: {
      password: "NewPass1!", password_confirmation: "DifferentPass2!"
    }
    assert_redirected_to edit_password_path(token)
    assert_not_nil flash[:alert]
  end

  test "PATCH /passwords/:token with invalid token redirects with alert" do
    patch password_path("invalid_token"), params: {
      password: "anything", password_confirmation: "anything"
    }
    assert_redirected_to new_password_path
    assert_not_nil flash[:alert]
  end
end
