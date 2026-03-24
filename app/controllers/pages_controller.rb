# app/controllers/pages_controller.rb
class PagesController < ApplicationController
  allow_unauthenticated_access only: [:login]

  before_action :require_admin, only: [:scanner, :trigger_scan, :scans, :stop_scan]

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
    @active_scans = Scan.for_org(current_org_id).running.count rescue 0
  end

  def scanner
    org_id   = Current.user.organization_id
    @assets  = Asset.where(organization_id: org_id).order(:ip_address)
    @exploits = Exploit.order(:id)
  end

  def trigger_scan
    unless Current.user.access_level == "admin"
      redirect_to scanner_path, alert: "You do not have permission to perform scans."
      return
    end

    org_id = Current.user.organization_id
    exploit_ids_param = params.dig(:trigger_scan, :exploit_ids) || []
    exploit_range = Array(exploit_ids_param).map(&:to_i).select { |id| id > 0 }

    asset_id = params[:asset_id].presence&.to_i
    ScanJob.perform_later(org_id, exploit_range, Current.user.id, asset_id)
    redirect_to scans_path, notice: "Scan queued."
  end

  def scans
    org_id = current_org_id
    @scans = Scan.for_org(org_id).order(created_at: :desc)
    @total_scans = @scans.count
    @running_scans = @scans.running.count
    @completed_scans = @scans.completed.count
    @failed_scans = @scans.failed.count
  end

  def stop_scan
    scan = Scan.for_org(current_org_id).running.find_by(id: params[:scan_id])
    scan&.update!(status: 'cancelled', end_time: Time.current)
    redirect_to scans_path, notice: "Scan stopped."
  end

  def reports
    @reports = Report.where(user_id: User.where(organization_id: current_org_id).select(:id)).order(generated_at: :desc)
    scan_ids = @reports.map(&:scan_id).compact
    scans = Scan.where(id: scan_ids)
    @critical_findings   = scans.sum(:critical_findings)
    @high_findings       = scans.sum(:high_findings)
    @medium_low_findings = scans.sum(:medium_findings) + scans.sum(:low_findings)
    @findings = Finding.where(scan_id: scan_ids).order(discovered_at: :desc).limit(200) rescue []
  end

  def settings
    @org = Organization.find_by(id: Current.session.user.organization_id)
  rescue
    @org = nil
  end

  def read_only_accounts
    @read_only_users = User.where(
      organization_id: Current.user.organization_id,
      access_level: "read_only"
    )
  end
end
