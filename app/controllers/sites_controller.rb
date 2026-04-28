class SitesController < ApplicationController
  before_action :require_admin

  def index
    @sites = Site.where(organization_id: current_org_id).includes(:agents, :assets).order(created_at: :desc)
  end

  def create
    site = Site.create!(
      name: params[:site][:name],
      network_range: params[:site][:network_range].presence,
      organization_id: current_org_id
    )
    log_activity(text: "Site <strong>#{ERB::Util.h(site.name)}</strong> created", color: 'magenta')
    redirect_to sites_path, notice: "Site created."
  rescue ActiveRecord::RecordInvalid => e
    redirect_to sites_path, alert: e.message
  end

  def destroy
    site = Site.find(params[:id])
    log_activity(text: "Site <strong>#{ERB::Util.h(site.name)}</strong> deleted", color: 'red')
    site.destroy
    redirect_to sites_path, notice: "Site deleted."
  rescue ActiveRecord::RecordNotFound
    redirect_to sites_path, alert: "Site not found."
  end
end
