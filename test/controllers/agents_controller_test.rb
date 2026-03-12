require "test_helper"

class AgentsControllerTest < ActionDispatch::IntegrationTest
  test "GET /agents redirects unauthenticated users to login" do
    get agents_path
    assert_redirected_to login_path
  end

  test "GET /agents returns 200 for admin" do
    sign_in_as(users(:admin_user))
    get agents_path
    assert_response :success
  end

  test "GET /agents redirects non-admin to root" do
    sign_in_as(users(:readonly_user))
    get agents_path
    assert_redirected_to root_path
  end

  test "POST /agents creates an agent" do
    sign_in_as(users(:admin_user))
    fake_keys = {
      private_key: "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
      public_key: "ssh-rsa fakekey agent-test",
      fingerprint: "SHA256:fakeprint"
    }
    Agent.any_instance.stub(:generate_ssh_keys, fake_keys) do
      assert_difference "Agent.count", 1 do
        post agents_path, params: { agent: { site_id: "", network_range: "" } }
      end
    end
    assert_response :redirect
  end

  test "DELETE /agents/:id destroys the agent" do
    sign_in_as(users(:admin_user))
    agent = agents(:agent_offline)
    assert_difference "Agent.count", -1 do
      delete agent_path(agent)
    end
    assert_redirected_to agents_path
  end

  test "GET /agents/status returns JSON" do
    sign_in_as(users(:admin_user))
    get status_agents_path, as: :json
    assert_response :success
    json = JSON.parse(response.body)
    assert json.key?("stats")
    assert json.key?("agents")
  end

  test "POST /agents/:agent_id/heartbeat updates last_seen (unauthenticated)" do
    agent = agents(:agent_offline)
    travel_to Time.current do
      post agent_heartbeat_path(agent_id: agent.agent_id),
           params: { platform: "Linux", hostname: "testbox" },
           as: :json
      assert_response :success
      agent.reload
      assert_in_delta Time.current.to_i, agent.last_seen.to_i, 2
      assert_equal "connected", agent.status
    end
  end

  test "POST heartbeat with unknown agent_id returns 404" do
    post agent_heartbeat_path(agent_id: "nonexistent-uuid"), as: :json
    assert_response :not_found
  end
end
