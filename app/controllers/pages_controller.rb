# app/controllers/pages_controller.rb
class PagesController < ApplicationController
  allow_unauthenticated_access only: [:login]

  before_action :require_admin, only: [:scanner, :trigger_scan, :scans, :stop_scan, :create_ro_account]

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

    @recent_findings = Finding.where(
      scan_id: Scan.for_org(org_id).select(:id)
    ).includes(:exploit, :asset).order(discovered_at: :desc).limit(10) rescue []

    @recent_activity = []
    begin
      recent_scans = Scan.for_org(org_id).order(created_at: :desc).limit(5)
      recent_scans.each do |scan|
        color = scan.status == 'completed' ? 'green' : scan.status == 'failed' ? 'red' : 'cyan'
        @recent_activity << { color: color, scan: scan }
      end
      last_agent = Agent.where(organization_id: org_id).order(last_seen: :desc).first
      @recent_activity << { color: last_agent.connected? ? 'green' : 'orange', agent: last_agent } if last_agent&.last_seen
      last_session = Session.joins(:user).where(users: { organization_id: org_id }).order(created_at: :desc).first
      @recent_activity << { color: 'blue', session: last_session } if last_session
    rescue => e
      Rails.logger.warn "recent_activity error: #{e.message}"
    end
  end

  def home_recent_findings
    org_id = current_org_id
    @recent_findings = Finding.where(
      scan_id: Scan.for_org(org_id).select(:id)
    ).includes(:exploit, :asset).order(discovered_at: :desc).limit(10) rescue []
    render partial: 'recent_findings', locals: { recent_findings: @recent_findings }
  end

  def scanner
    org_id    = Current.user.organization_id
    @assets   = Asset.where(organization_id: org_id).includes(:site).order(:ip_address)
    @sites    = Site.where(organization_id: org_id)
    @profiles = ScanProfile.where(organization_id: org_id)
  end

  def trigger_scan
    org_id = Current.user.organization_id

    # Resolve target asset IDs
    asset_ids = case params[:target_mode]
    when 'site'
      Asset.where(organization_id: org_id, site_id: params[:site_id]).pluck(:id)
    when 'cidr'
      require 'ipaddr'
      range = IPAddr.new(params[:cidr_range].to_s) rescue nil
      range ? Asset.where(organization_id: org_id).select { |a|
        range.include?(IPAddr.new(a.ip_address.to_s.split('/').first)) rescue false
      }.map(&:id) : []
    else # 'asset'
      Array(params[:asset_ids]).map(&:to_i).select { |id| id > 0 }
    end

    if asset_ids.empty?
      redirect_to scanner_path, alert: "No targets selected."
      return
    end

    filter_params = {
      platform:   params[:platform].presence || 'any',
      severities: Array(params[:severities]).presence
    }.compact

    if params[:profile_id].present?
      profile = ScanProfile.find_by(id: params[:profile_id], organization_id: org_id)
      if profile&.exploit_ids&.any?
        allowlist = Exploit.where(id: profile.exploit_ids).pluck(:metasploit_module).compact
        filter_params[:module_allowlist] = allowlist if allowlist.any?
      end
    end

    scan_options = {
      port_override: params[:port_override].presence,
      timeout:       params[:timeout].presence&.to_i,
      use_agent:     params[:use_agent] == 'true'
    }.compact

    ScanJob.perform_later(org_id, filter_params, Current.user.id, asset_ids, scan_options)
    redirect_to scans_path, notice: "Scan queued for #{asset_ids.size} target(s)."
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
    @findings = Finding.where(scan_id: scan_ids).includes(:exploit, :asset).order(discovered_at: :desc).limit(200) rescue []
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

  def create_ro_account
    # form rendered by view; submission handled by ReadOnlyAccountsController#create
  end

  private

end
