class AssetsController < ApplicationController

  allow_unauthenticated_access

  def index
    # Show list of all assets
    @@assets ||= []
    @assets = @@assets
  end

  def new
    # Show the form to add new asset
  end

  def create
    # Get form data 
    @asset_config = params.permit(
      :scanMode,      
      :scope,
      :network,
      :exclude,
      :port,
      :os,
      :asset,
      :scanType,      
      :credential,
      :schedule,
      :cve,
      format: []      # Array for checkboxes
    )

    # connect database later
    @@assets ||= []
    @@assets << @asset_config.to_h
    
    # Redirect back to assets list
    redirect_to assets_path, notice: 'Asset added successfully!'
  end

  def show
    # Show individual asset details
    @@assets ||= []
    @asset = @@assets[params[:id].to_i - 1]
    
    if @asset
      render plain: "Asset Details:\n\n#{@asset.inspect}"
    else
      redirect_to assets_path, alert: 'Asset not found'
    end
  end
end