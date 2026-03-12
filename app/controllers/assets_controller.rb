class AssetsController < ApplicationController

  before_action :require_admin

  def index
    @assets = Asset.where(organization_id: current_org_id).order(created_at: :desc)
  end

  def new
    @sites = Site.where(organization_id: current_org_id)
  end

  def create
    scan_config = params.permit(:scanMode, :scope, :exclude, :port, :os, :asset, :scanType, :credential, :schedule, :cve, format: []).to_h
    asset = Asset.new(
      ip_address: params[:network],
      organization_id: current_org_id,
      site_id: params[:site_id].presence,
      scan_config: scan_config
    )

    if asset.ip_address.nil? && params[:network].present?
      redirect_to new_asset_path, alert: "Invalid IP address: '#{params[:network]}'"
      return
    end

    asset.save!
    redirect_to assets_path, notice: 'Asset added successfully!'
  rescue => e
    redirect_to new_asset_path, alert: "Failed to add asset: #{e.message}"
  end

  def show
    @asset = Asset.find(params[:id])
  rescue ActiveRecord::RecordNotFound
    redirect_to assets_path, alert: 'Asset not found'
  end

  def destroy
    asset = Asset.find(params[:id])
    asset.destroy
    redirect_to assets_path, notice: 'Asset deleted.'
  rescue ActiveRecord::RecordNotFound
    redirect_to assets_path, alert: 'Asset not found'
  end
end
