require "test_helper"

class Api::AgentsApiControllerTest < ActionDispatch::IntegrationTest
  def setup
    @admin_key    = users(:admin_user).api_key
    @readonly_key = users(:readonly_user).api_key
  end

  test "GET /api/:key/agents returns list for admin" do
    get "/api/#{@admin_key}/agents"
    assert_response :success
    json = JSON.parse(response.body)
    assert_kind_of Array, json["agents"]
  end

  test "GET /api/:key/agents returns 403 for readonly user" do
    get "/api/#{@readonly_key}/agents"
    assert_response :forbidden
  end

  test "GET /api/:key/agents/status returns stats" do
    get "/api/#{@admin_key}/agents/status"
    assert_response :success
    json = JSON.parse(response.body)
    assert json["stats"].key?("total")
    assert json["stats"].key?("connected")
    assert json["stats"].key?("offline")
    assert_kind_of Array, json["agents"]
  end

  test "POST /api/:key/agents creates an agent" do
    assert_difference "Agent.count", 1 do
      post "/api/#{@admin_key}/agents", params: { network_range: "10.50.0.0/24" }
    end
    assert_response :created
    json = JSON.parse(response.body)
    assert json["agent"]["agent_id"].present?
  end

  test "POST /api/:key/agents returns 403 for readonly user" do
    post "/api/#{@readonly_key}/agents", params: { network_range: "10.0.0.0/24" }
    assert_response :forbidden
  end

  test "DELETE /api/:key/agents/:id deletes agent" do
    agent = agents(:agent_offline)
    assert_difference "Agent.count", -1 do
      delete "/api/#{@admin_key}/agents/#{agent.id}"
    end
    assert_response :success
    json = JSON.parse(response.body)
    assert json["deleted"]
  end

  test "DELETE /api/:key/agents/:id returns 404 for missing agent" do
    delete "/api/#{@admin_key}/agents/0"
    assert_response :not_found
  end

  test "DELETE /api/:key/agents/:id returns 403 for readonly user" do
    agent = agents(:agent_offline)
    delete "/api/#{@readonly_key}/agents/#{agent.id}"
    assert_response :forbidden
  end

  test "GET /api/:key/agents with invalid key returns 401" do
    get "/api/bad_key/agents"
    assert_response :unauthorized
  end

  test "POST /api/:key/agents returns 422 when create fails" do
    Agent.stub(:create!, ->(*) { raise ActiveRecord::RecordInvalid.new(Agent.new) }) do
      post "/api/#{@admin_key}/agents", params: { network_range: "boom" }
    end
    assert_response :unprocessable_entity
    assert JSON.parse(response.body)["error"].present?
  end

  test "GET /api/:key/agents/:id/download sends a zip" do
    agent = agents(:agent_offline)
    AgentZipBuilder.stub(:build, ->(*) {
      f = Tempfile.new(["fake", ".zip"])
      f.write("PK\x03\x04fake")
      f.flush
      f.path
    }) do
      get "/api/#{@admin_key}/agents/#{agent.id}/download"
    end
    assert_response :success
    assert_equal "application/zip", response.content_type
    assert_includes response.headers["Content-Disposition"], "attachment"
  end

  test "GET /api/:key/agents/:id/download 404 for missing agent" do
    get "/api/#{@admin_key}/agents/0/download"
    assert_response :not_found
  end
end
