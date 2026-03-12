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

  test "invalid without email" do
    user = User.new(name: "No Email", password: "password", organization_id: @org.id, access_level: "admin")
    assert_not user.valid?
    assert_includes user.errors[:email_address], "can't be blank"
  end

  test "duplicate email in same org is rejected" do
    user = User.new(
      name: "Duplicate",
      email_address: "admin@example.com",
      password: "password",
      organization_id: @org.id,
      access_level: "admin"
    )
    assert_not user.valid?
    assert_includes user.errors[:email_address], "is already registered in this organization"
  end

  test "same email in different org is allowed" do
    other = organizations(:other_org)
    user = User.new(
      name: "Other Org User",
      email_address: "admin@example.com",
      password: "password",
      organization_id: other.id,
      access_level: "admin"
    )
    assert user.valid?
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
