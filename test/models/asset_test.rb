require "test_helper"

class AssetTest < ActiveSupport::TestCase
  def setup
    @org = organizations(:acme)
    @site = sites(:main_site)
  end

  test "valid asset saves successfully" do
    asset = Asset.new(ip_address: "10.0.0.5", organization_id: @org.id)
    assert asset.valid?
  end

  test "invalid without ip_address" do
    asset = Asset.new(organization_id: @org.id)
    assert_not asset.valid?
    assert_includes asset.errors[:ip_address], "can't be blank"
  end

  test "ip within site network range is valid" do
    asset = Asset.new(
      ip_address: "192.168.1.50",
      organization_id: @org.id,
      site: @site
    )
    assert asset.valid?, asset.errors.full_messages.to_s
  end

  test "ip outside site network range is invalid" do
    asset = Asset.new(
      ip_address: "10.0.0.1",
      organization_id: @org.id,
      site: @site
    )
    assert_not asset.valid?
    assert asset.errors[:ip_address].any? { |e| e.include?("outside the site's network range") }
  end

  test "ip validation skipped when site has no network range" do
    site = sites(:open_site)
    asset = Asset.new(ip_address: "172.16.0.1", organization_id: @org.id, site: site)
    assert asset.valid?
  end

  test "ip validation skipped when no site assigned" do
    asset = Asset.new(ip_address: "1.2.3.4", organization_id: @org.id)
    assert asset.valid?
  end
end
