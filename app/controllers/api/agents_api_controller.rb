module Api
  class AgentsApiController < ApiController
    before_action :require_api_admin!

    def index
      agents = Agent.where(organization_id: @current_user.organization_id).order(created_at: :desc)
      render json: { agents: agents.map { |a| agent_json(a) } }
    end

    # Body: site_id (optional), network_range (optional)
    def create
      agent = Agent.create!(
        organization_id: @current_user.organization_id,
        site_id:         params[:site_id].presence,
        network_range:   params[:network_range].presence
      )
      render json: { agent: agent_json(agent) }, status: :created
    rescue => e
      render json: { error: e.message }, status: :unprocessable_entity
    end

    def destroy
      agent = Agent.where(organization_id: @current_user.organization_id).find(params[:id])
      agent.destroy
      render json: { deleted: true, id: params[:id].to_i }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Agent not found" }, status: :not_found
    end

    def download
      agent    = Agent.where(organization_id: @current_user.organization_id).find(params[:id])
      zip_path = AgentZipBuilder.build(agent, "100.69.88.107", 3000)
      send_data File.binread(zip_path),
                filename:    "scanner-agent-#{agent.agent_id}.zip",
                type:        "application/zip",
                disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Agent not found" }, status: :not_found
    end

    def status
      agents = Agent.where(organization_id: @current_user.organization_id)
      render json: {
        stats: {
          total:        agents.count,
          connected:    agents.count(&:connected?),
          offline:      agents.count { |a| !a.connected? },
          sites_active: agents.select(&:connected?).map(&:site_id).compact.uniq.count
        },
        agents: agents.map { |a| agent_json(a) }
      }
    end

    private

    def agent_json(a)
      {
        id:            a.id,
        agent_id:      a.agent_id,
        site_id:       a.site_id,
        network_range: a.network_range,
        platform:      a.platform,
        hostname:      a.hostname,
        status:        a.status,
        connected:     a.connected?,
        last_seen:     a.last_seen,
        tunnel_port:   a.tunnel_port,
        created_at:    a.created_at
      }
    end
  end
end
