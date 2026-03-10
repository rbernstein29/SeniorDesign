class SitesController < ApplicationController
  def index
    @sites = Site.where(organization_id: current_org_id).order(created_at: :desc)
  end

  def create
    Site.create!(
      name: params[:site][:name],
      network_range: params[:site][:network_range].presence,
      organization_id: current_org_id
    )
    redirect_to sites_path, notice: "Site created."
  rescue ActiveRecord::RecordInvalid => e
    redirect_to sites_path, alert: e.message
  end

  def destroy
    Site.find(params[:id]).destroy
    redirect_to sites_path, notice: "Site deleted."
  rescue ActiveRecord::RecordNotFound
    redirect_to sites_path, alert: "Site not found."
  end
end
