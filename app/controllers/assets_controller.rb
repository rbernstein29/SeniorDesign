# app/controllers/assets_controller.rb
class AssetsController < ApplicationController
  def index
    # Show list of all assets
    @assets = Asset.all 
  end
  
  def new
    # Show form to add new asset
  end
  
  def create
    # Save the new asset configuration
    @asset_config = params.permit(
      :scan_mode, :scope, :network, :exclude, :port,
      :os, :asset, :scan_type, :credential, :schedule, :cve,
      format: []
    )
    
    #Test display of received parameters
    render plain: "✓ Asset Configuration Received!\n\n#{@asset_config.inspect}"
    
  end
end