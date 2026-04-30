require "test_helper"

class AuthenticationTest < ActionDispatch::IntegrationTest
  test "expired session is destroyed and cookie cleared on next request" do
    sign_in_as(users(:admin_user))
    session = Current.session || Session.order(:id).last
    session = users(:admin_user).sessions.order(:id).last
    session.update_column(:last_active_at, 1.day.ago)

    assert_difference "Session.count", -1 do
      get home_path
    end
    assert_redirected_to login_path
  end

  test "JSON request without session returns 401 instead of redirect" do
    get home_path, headers: { "Accept" => "application/json" }, params: { format: :json }
    assert_response :unauthorized
    assert_equal "Unauthenticated", JSON.parse(response.body)["error"]
  end

  test "authenticated? helper returns truthy for signed-in user" do
    sign_in_as(users(:admin_user))
    get home_path
    assert_response :success
  end

  test "authenticated? exposes resume_session result for use in views" do
    ctrl = ApplicationController.new
    called = 0
    ctrl.define_singleton_method(:resume_session) { called += 1; :ok }
    assert_equal :ok, ctrl.send(:authenticated?)
    assert_equal 1, called
  end

  test "start_new_session_for retries after RecordNotUnique sequence collision" do
    user = users(:admin_user)
    attempt = 0
    fake_relation = Object.new
    fake_relation.define_singleton_method(:create!) do |**_attrs|
      attempt += 1
      raise ActiveRecord::RecordNotUnique.new("dup id") if attempt == 1
      session = Session.new(user_id: user.id, last_active_at: Time.current)
      session.id = 9_999_999
      session
    end

    user.define_singleton_method(:sessions) { fake_relation }
    User.stub(:authenticate_by, user) do
      post session_path, params: { email_address: user.email_address, password: TEST_FIXTURE_PASSWORD }
    end
    assert_equal 2, attempt
  end
end
