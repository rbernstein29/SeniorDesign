require "test_helper"

class SessionTest < ActiveSupport::TestCase
  test "not expired when last_active_at is recent" do
    session = sessions(:admin_session)
    session.last_active_at = 30.minutes.ago
    assert_not session.expired?
  end

  test "expired when last_active_at is over 1 hour ago" do
    session = sessions(:admin_session)
    session.last_active_at = 2.hours.ago
    assert session.expired?
  end

  test "expired when last_active_at is exactly at the boundary" do
    session = sessions(:admin_session)
    session.last_active_at = (Session::EXPIRY + 1.second).ago
    assert session.expired?
  end

  test "belongs to a user" do
    session = sessions(:admin_session)
    assert_equal users(:admin_user), session.user
  end
end
