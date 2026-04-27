module Api
  class SitesApiController < ApiController
    before_action :require_api_admin!, only: [:create, :destroy]

    def index
      sites = Site.where(organization_id: @current_user.organization_id)
                  .includes(:agents, :assets)
                  .order(created_at: :desc)
      render json: { sites: sites.map { |s| site_json(s) } }
    end

    # Body: name, network_range
    def create
      site = Site.create!(
        name:            params[:name].to_s.strip,
        network_range:   params[:network_range].presence,
        organization_id: @current_user.organization_id
      )
      render json: { site: site_json(site) }, status: :created
    rescue ActiveRecord::RecordInvalid => e
      render json: { error: e.message }, status: :unprocessable_entity
    end

    def destroy
      site = Site.where(organization_id: @current_user.organization_id).find(params[:id])
      site.destroy
      render json: { deleted: true, id: params[:id].to_i }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Site not found" }, status: :not_found
    end

    private

    def site_json(s)
      {
        id:            s.id,
        name:          s.name,
        network_range: s.network_range,
        agents_count:  s.agents.size,
        assets_count:  s.assets.size,
        created_at:    s.created_at
      }
    end
  end
end
