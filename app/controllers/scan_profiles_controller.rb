class ScanProfilesController < ApplicationController
  before_action :require_admin

  def index
    @profiles = ScanProfile.where(organization_id: current_org_id).order(:name)
  end

  def new
    @exploits = Exploit.order(:severity, :name)
  end

  def create
    profile = ScanProfile.new(
      organization_id: current_org_id,
      name:            params[:name].to_s.strip,
      description:     params[:description].presence,
      exploit_ids:     Array(params[:exploit_ids]).map(&:to_i).select { |id| id > 0 }
    )
    if profile.save
      redirect_to scan_profiles_path, notice: "Profile '#{profile.name}' saved."
    else
      redirect_to new_scan_profile_path, alert: profile.errors.full_messages.join(', ')
    end
  end

  def destroy
    ScanProfile.where(organization_id: current_org_id).find(params[:id]).destroy
    redirect_to scan_profiles_path, notice: 'Profile deleted.'
  rescue ActiveRecord::RecordNotFound
    redirect_to scan_profiles_path, alert: 'Profile not found.'
  end
end
