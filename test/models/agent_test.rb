require "test_helper"

class AgentTest < ActiveSupport::TestCase
  def setup
    @agent = agents(:agent_connected)
    @offline = agents(:agent_offline)
  end

  test "connected? returns true when last_seen is recent" do
    @agent.last_seen = 10.seconds.ago
    assert @agent.connected?
  end

  test "connected? returns false when last_seen is old" do
    @agent.last_seen = 60.seconds.ago
    assert_not @agent.connected?
  end

  test "connected? returns false when last_seen is nil" do
    @agent.last_seen = nil
    assert_not @agent.connected?
  end

  test "heartbeat! updates last_seen and status" do
    travel_to Time.current do
      @offline.heartbeat!
      @offline.reload
      assert_in_delta Time.current.to_i, @offline.last_seen.to_i, 2
      assert_equal "connected", @offline.status
    end
  end

  test "scan_targets returns IPs of site assets" do
    targets = @agent.scan_targets
    assert_includes targets, "192.168.1.10"
  end

  test "scan_targets returns empty array when agent has no site" do
    @offline.update_column(:site_id, nil)
    assert_equal [], @offline.scan_targets
  end

  test "package_config returns correct keys" do
    config = @agent.package_config
    assert_equal @agent.agent_id, config[:agent_id]
    assert_equal @agent.tunnel_port, config[:tunnel_port]
    assert_equal @agent.ssh_private_key, config[:ssh_private_key]
    assert config.key?(:scanner_server)
  end

  test "find_for_target returns connected agent for matching IP" do
    @agent.update_column(:last_seen, Time.current)
    org_id = @agent.organization_id
    found = Agent.find_for_target(org_id, "192.168.1.10")
    assert_equal @agent, found
  end

  test "find_for_target returns nil for disconnected agent" do
    @agent.update_column(:last_seen, 2.minutes.ago)
    found = Agent.find_for_target(@agent.organization_id, "192.168.1.10")
    assert_nil found
  end
end
