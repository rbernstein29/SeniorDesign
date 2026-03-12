require "test_helper"

class OrganizationTest < ActiveSupport::TestCase
  test "valid organization saves successfully" do
    org = Organization.new(org_name: "New Org")
    assert org.valid?
    assert org.save
  end

  test "invalid without org_name" do
    org = Organization.new
    assert_not org.valid?
    assert_includes org.errors[:org_name], "can't be blank"
  end

  test "duplicate org_name is rejected" do
    org = Organization.new(org_name: "Acme Corp")
    assert_not org.valid?
    assert_includes org.errors[:org_name], "is already registered"
  end

  test "org_name uniqueness is case insensitive" do
    org = Organization.new(org_name: "ACME CORP")
    assert_not org.valid?
  end

  test "has many users" do
    org = organizations(:acme)
    assert_includes org.users, users(:admin_user)
  end
end
