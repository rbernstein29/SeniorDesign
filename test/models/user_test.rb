require "test_helper"

class UserTest < ActiveSupport::TestCase
  def setup
    @org = organizations(:acme)
  end

  test "valid user saves successfully" do
    user = User.new(
      name: "Test User",
      email_address: "newuser@example.com",
      password: "password",
      organization_id: @org.id,
      access_level: "admin"
    )
    assert user.valid?
    assert user.save
  end

  test "invalid without email fails to save" do
    user = User.new(name: "No Email", password: "password", organization_id: @org.id, access_level: "admin")
    assert_not user.save
  end

  test "duplicate email is rejected" do
    user = User.new(
      name: "Duplicate",
      email_address: "admin@example.com",
      password: "password",
      organization_id: @org.id,
      access_level: "admin"
    )
    assert_not user.valid?
    assert_includes user.errors[:email_address], "is already registered"
  end

  test "email is normalized to lowercase" do
    user = User.create!(
      name: "Caps User",
      email_address: "CAPS@EXAMPLE.COM",
      password: "password",
      organization_id: @org.id,
      access_level: "read_only"
    )
    assert_equal "caps@example.com", user.email_address
  end

  test "password authentication works" do
    user = users(:admin_user)
    assert user.authenticate("password")
    assert_not user.authenticate("wrongpassword")
  end
end
