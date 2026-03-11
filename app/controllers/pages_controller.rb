# app/controllers/pages_controller.rb
class PagesController < ApplicationController
  allow_unauthenticated_access only: [:login]

  def login
    # login page
  end

  def home
    org_id       = current_org_id
    @assets      = Asset.where(organization_id: org_id).order(created_at: :desc) rescue []
    @agents      = Agent.where(organization_id: org_id) rescue []
    @sites       = Site.where(organization_id: org_id) rescue []
    org_user_ids = User.where(organization_id: org_id).select(:id)
    @reports     = Report.where(user_id: org_user_ids) rescue []
    @users_count = User.where(organization_id: org_id).count rescue 0
    @last_scan   = Report.where(user_id: org_user_ids).maximum(:generated_at) rescue nil
  end

  def scanner
  end

  def trigger_scan
    unless Current.user.access_level == "admin"
      redirect_to scanner_path, alert: "You do not have permission to perform scans."
      return
    end

    org_id = Current.user.organization_id
    exploit_ids_str = params[:exploit_ids].presence || '1-5'
    exploit_range = []

    exploit_ids_str.split(',').each do |part|
      if part.include?('-')
        start_id, end_id = part.split('-').map(&:to_i)
        exploit_range.concat((start_id..end_id).to_a)
      else
        exploit_range << part.to_i
      end
    end
    exploit_range.uniq!
    exploit_range.sort!

    ScanJob.perform_later(org_id, exploit_range, Current.user.id)
    redirect_to scanner_path, notice: "Scan queued. Results will appear in Reports when complete."
  end

  def scans
  end

  def reports
    @reports = Report.where(user_id: User.where(organization_id: current_org_id).select(:id)).order(generated_at: :desc)
  end

  def settings
    @org = Organization.find_by(id: Current.session.user.organization_id)
  rescue
    @org = nil
  end
end
