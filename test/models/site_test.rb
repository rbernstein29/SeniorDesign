require "test_helper"

class SiteTest < ActiveSupport::TestCase
  test "valid site saves successfully" do
    site = Site.new(name: "Test Site", organization_id: ActiveRecord::FixtureSet.identify(:acme))
    assert site.valid?
  end

  test "name is required" do
    site = Site.new(organization_id: ActiveRecord::FixtureSet.identify(:acme))
    assert_not site.valid?
    assert_includes site.errors[:name], "can't be blank"
  end

  test "belongs to organization via organization_id" do
    site = sites(:main_site)
    assert_equal ActiveRecord::FixtureSet.identify(:acme), site.organization_id
  end
end
