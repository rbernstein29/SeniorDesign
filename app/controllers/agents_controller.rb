class AgentsController < ApplicationController
  include ActionView::Helpers::DateHelper
  skip_before_action :verify_authenticity_token
  allow_unauthenticated_access only: [:heartbeat]

  before_action :require_admin
  skip_before_action :require_admin, only: [:heartbeat]

  # GET /agents
  def index
    @agents = Agent.where(organization_id: current_org_id).order(created_at: :desc)
    @sites = Site.where(organization_id: current_org_id).order(name: :asc).select { |s| s.agents.empty? }
  end

  # POST /agents
  def create
    agent = Agent.create!(
      organization_id: current_org_id,
      site_id: params.dig(:agent, :site_id).presence,
      network_range: params.dig(:agent, :network_range).presence
    )
    redirect_to download_agent_path(agent)
  rescue => e
    redirect_to agents_path, alert: "Failed to create agent: #{e.message}"
  end

  # DELETE /agents/:id
  def destroy
    agent = Agent.where(organization_id: current_org_id).find(params[:id])
    agent.destroy
    redirect_to agents_path
  rescue => e
    redirect_to agents_path, alert: "Failed to delete agent: #{e.message}"
  end

  # GET /agents/:id/download
  def download
    agent       = Agent.find(params[:id])
    server_ip   = "100.69.88.107"
    server_port = request.port
    zip_path    = AgentZipBuilder.build(agent, server_ip, server_port)
    send_file zip_path,
              filename:    "scanner-agent-#{agent.agent_id}.zip",
              type:        "application/zip",
              disposition: "attachment"
  end

  # GET /agents/status.json
  def status
    agents = Agent.where(organization_id: current_org_id)
    render json: {
      stats: {
        total:        agents.count,
        connected:    agents.count(&:connected?),
        offline:      agents.count { |a| !a.connected? },
        sites_active: agents.select(&:connected?).map(&:site_id).compact.uniq.count
      },
      agents: agents.map do |a|
        {
          id:        a.agent_id,
          connected: a.connected?,
          last_seen: a.last_seen ? "#{time_ago_in_words(a.last_seen)} ago" : "Never",
          platform:  a.platform,
          hostname:  a.hostname
        }
      end
    }
  end

  # POST /agents/:agent_id/heartbeat
  def heartbeat
    agent = Agent.find_by!(agent_id: params[:agent_id])

    update_params = { last_seen: Time.current, status: 'connected' }
    update_params[:platform] = params[:platform] if params[:platform].present?
    update_params[:hostname] = params[:hostname] if params[:hostname].present?

    agent.update!(update_params)

    render json: { success: true, agent_id: agent.agent_id, last_seen: agent.last_seen }
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'Agent not found' }, status: 404
  rescue => e
    render json: { error: e.message }, status: 500
  end
end
