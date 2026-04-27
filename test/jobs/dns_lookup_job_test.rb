require "test_helper"

class DnsLookupJobTest < ActiveSupport::TestCase
  include ActiveJob::TestHelper

  def setup
    @asset = assets(:asset_one)
    @asset.update!(hostname: nil)
  end

  # ── enqueue ───────────────────────────────────────────────────────────────────

  test "DnsLookupJob is queued to the default queue" do
    assert_equal "default", DnsLookupJob.queue_name
  end

  # ── perform ───────────────────────────────────────────────────────────────────

  test "perform sets hostname when reverse DNS resolves" do
    Resolv.stub(:getname, "resolved.hostname.local") do
      DnsLookupJob.new.perform(@asset.id)
    end
    assert_equal "resolved.hostname.local", @asset.reload.hostname
  end

  test "perform sets hostname to No Domain Name when DNS does not resolve" do
    Resolv.stub(:getname, ->(_ip) { raise Resolv::ResolvError }) do
      DnsLookupJob.new.perform(@asset.id)
    end
    assert_equal "No Domain Name", @asset.reload.hostname
  end

  test "perform skips asset that already has a hostname" do
    @asset.update!(hostname: "already-set.local")
    Resolv.stub(:getname, ->(_ip) { raise "should not be called" }) do
      DnsLookupJob.new.perform(@asset.id)
    end
    assert_equal "already-set.local", @asset.reload.hostname
  end

  test "perform does nothing when asset is not found" do
    assert_nothing_raised do
      DnsLookupJob.new.perform(-999)
    end
  end
end
