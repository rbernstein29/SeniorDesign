require "test_helper"

class AccountsControllerTest < ActionDispatch::IntegrationTest

  # ── POST /accounts (registration) ───────────────────────────────────────────

  test "POST /accounts creates organization and admin user" do
    assert_difference ["Organization.count", "User.count"], 1 do
      post accounts_path, params: {
        organization: { org_name: "Brand New Org" },
        user: { name: "Founder", email_address: "founder@brandnew.com",
                password: TEST_FIXTURE_PASSWORD, password_confirmation: TEST_FIXTURE_PASSWORD }
      }
    end
    assert_redirected_to verify_pending_path
  end

  test "POST /accounts sends verification email" do
    assert_emails 1 do
      post accounts_path, params: {
        organization: { org_name: "Email Org" },
        user: { name: "Test", email_address: "test@emailorg.com",
                password: TEST_FIXTURE_PASSWORD, password_confirmation: TEST_FIXTURE_PASSWORD }
      }
    end
  end

  test "POST /accounts with duplicate org_name redirects with alert" do
    assert_no_difference "Organization.count" do
      post accounts_path, params: {
        organization: { org_name: "Acme Corp" },
        user: { name: "Dup", email_address: "dup@acme.com",
                password: TEST_FIXTURE_PASSWORD, password_confirmation: TEST_FIXTURE_PASSWORD }
      }
    end
    assert_redirected_to login_path
    assert_not_nil flash[:alert]
  end

  # ── GET /verify_pending ──────────────────────────────────────────────────────

  test "GET /verify_pending renders without authentication" do
    get verify_pending_path
    assert_response :success
  end

  # ── GET /verify_email/:token ─────────────────────────────────────────────────

  test "GET /verify_email/:token with valid token verifies user and creates session" do
    user = User.create!(
      name: "Unverified", email_address: "unverified@test.com",
      password: TEST_FIXTURE_PASSWORD,
      organization_id: organizations(:acme).id,
      access_level: "read_only",
      email_verified_at: nil
    )
    token = user.generate_token_for(:email_verification)

    assert_difference "Session.count", 1 do
      get verify_email_path(token)
    end
    assert_redirected_to root_path
    user.reload
    assert_not_nil user.email_verified_at
  end

  test "GET /verify_email/:token with invalid token redirects with alert" do
    get verify_email_path("totally_invalid_token")
    assert_redirected_to login_path
    assert_not_nil flash[:alert]
  end

  test "GET /verify_email/:token with already-used token is invalid" do
    user = User.create!(
      name: "Already Verified", email_address: "already@test.com",
      password: TEST_FIXTURE_PASSWORD,
      organization_id: organizations(:acme).id,
      access_level: "read_only",
      email_verified_at: nil
    )
    token = user.generate_token_for(:email_verification)
    user.update_column(:email_verified_at, Time.current)

    # Token is now invalid because email_verified_at changed (the token digest key)
    get verify_email_path(token)
    assert_redirected_to login_path
  end

  # ── POST /resend_verification ─────────────────────────────────────────────────

  test "POST /resend_verification always shows same notice regardless of email" do
    # Known unverified email
    assert_emails 1 do
      user = User.create!(
        name: "Resend", email_address: "resend@test.com",
        password: TEST_FIXTURE_PASSWORD,
        organization_id: organizations(:acme).id,
        access_level: "read_only",
        email_verified_at: nil
      )
      post resend_verification_path, params: { email_address: user.email_address }
    end
    assert_redirected_to verify_pending_path
    assert_not_nil flash[:notice]
  end

  test "POST /resend_verification with unknown email shows same notice (no enumeration)" do
    assert_emails 0 do
      post resend_verification_path, params: { email_address: "nobody@nowhere.com" }
    end
    assert_redirected_to verify_pending_path
    assert_not_nil flash[:notice]
  end

  test "POST /resend_verification does not resend to already-verified user" do
    assert_emails 0 do
      post resend_verification_path, params: { email_address: users(:admin_user).email_address }
    end
    assert_redirected_to verify_pending_path
  end

  # ── PATCH /accounts/generate_api_key ─────────────────────────────────────────

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

  # ── DELETE /accounts ──────────────────────────────────────────────────────────

  test "DELETE /accounts destroys admin user's entire organization" do
    # Create a fresh org so we don't touch fixture data used by other tests
    org  = Organization.create!(org_name: "Doomed Org")
    user = User.create!(
      name: "Admin Doom", email_address: "doom@doomed.com",
      password: TEST_FIXTURE_PASSWORD,
      organization_id: org.id,
      access_level: "admin",
      email_verified_at: Time.current
    )
    sign_in_as(user)

    assert_difference "Organization.count", -1 do
      delete account_path(user)
    end
    assert_redirected_to login_path
  end

  test "DELETE /accounts destroys read_only user only, not the org" do
    user = users(:readonly_user)
    sign_in_as(user)
    assert_no_difference "Organization.count" do
      assert_difference "User.count", -1 do
        delete account_path(user)
      end
    end
    assert_redirected_to login_path
  end

  test "POST /accounts redirects to verify_pending when verification email fails" do
    EmailVerifyMailer.stub(:verify, ->(*) { raise "smtp gone" }) do
      post accounts_path, params: {
        organization: { org_name: "Mailer Fail Org" },
        user: { name: "MF", email_address: "mailfail@example.com",
                password: TEST_FIXTURE_PASSWORD, password_confirmation: TEST_FIXTURE_PASSWORD }
      }
    end
    assert_redirected_to verify_pending_path
  end

  test "POST /accounts surfaces RecordNotUnique on duplicate email" do
    User.stub(:create!, ->(*) { raise ActiveRecord::RecordNotUnique.new("dup") }) do
      post accounts_path, params: {
        organization: { org_name: "Unique Org Test" },
        user: { name: "Dup", email_address: "dup@new.com",
                password: TEST_FIXTURE_PASSWORD, password_confirmation: TEST_FIXTURE_PASSWORD }
      }
    end
    assert_redirected_to login_path
    assert_match(/already registered/, flash[:alert].to_s)
  end

  test "POST /resend_verification swallows mailer errors and shows generic notice" do
    user = User.create!(
      name: "RV2", email_address: "rv2@test.com",
      password: TEST_FIXTURE_PASSWORD,
      organization_id: organizations(:acme).id,
      access_level: "read_only",
      email_verified_at: nil
    )
    EmailVerifyMailer.stub(:verify, ->(*) { raise "smtp gone" }) do
      post resend_verification_path, params: { email_address: user.email_address }
    end
    assert_redirected_to verify_pending_path
    assert_not_nil flash[:notice]
  end
end
