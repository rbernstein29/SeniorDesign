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
    assert_difference "Agent.count", 1 do
      post agents_path, params: { agent: { site_id: "", network_range: "" } }
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

  test "GET /agents/status returns JSON with stats key" do
    sign_in_as(users(:admin_user))
    get status_agents_path, as: :json
    assert_response :success
    assert_includes response.content_type, "json"
    body = JSON.parse(response.body)
    assert body.key?("stats")
  end

  test "DELETE /agents/:id for another org's agent does not destroy it" do
    sign_in_as(users(:other_org_user))
    assert_no_difference "Agent.count" do
      delete agent_path(agents(:agent_offline))
    end
  end

  # ── GET /agents/:id/download ──────────────────────────────────────────────────

  test "GET /agents/:id/download redirects unauthenticated to login" do
    get download_agent_path(agents(:agent_connected))
    assert_redirected_to login_path
  end

  test "GET /agents/:id/download redirects readonly user to root" do
    sign_in_as(users(:readonly_user))
    get download_agent_path(agents(:agent_connected))
    assert_redirected_to root_path
  end

  test "GET /agents/:id/download returns zip attachment for admin" do
    sign_in_as(users(:admin_user))
    agent = agents(:agent_connected)
    get download_agent_path(agent)
    assert_response :success
    assert_equal "application/zip", response.content_type
    assert_includes response.headers["Content-Disposition"], "attachment"
    assert_includes response.headers["Content-Disposition"], agent.agent_id
  end

  test "POST /agents surfaces creation errors with alert" do
    sign_in_as(users(:admin_user))
    Agent.stub(:create!, ->(*) { raise "no agents allowed" }) do
      post agents_path, params: { agent: { site_id: "", network_range: "" } }
    end
    assert_redirected_to agents_path
    assert_match(/Failed to create agent/, flash[:alert].to_s)
  end

  test "POST heartbeat returns 500 on unexpected error" do
    Agent.stub(:find_by!, ->(*) { raise "db crashed" }) do
      post agent_heartbeat_path(agent_id: "anything"), as: :json
    end
    assert_response :internal_server_error
    assert_match(/db crashed/, JSON.parse(response.body)["error"])
  end
end
