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

  def scanner
    org_id    = Current.user.organization_id
    @assets   = Asset.where(organization_id: org_id).includes(:site).order(:ip_address)
    @sites    = Site.where(organization_id: org_id)
    @exploits = Exploit.order(:severity, :name)
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

    # Resolve exploit IDs
    exploit_ids = case params[:exploit_mode]
    when 'profile'
      ScanProfile.find_by(id: params[:profile_id], organization_id: org_id)&.exploit_ids || []
    when 'auto'
      os_list = Asset.where(id: asset_ids).pluck(:scan_config).map { |c|
        (c || {})['os']
      }.compact.uniq
      auto_select_exploits(os_list)
    else # 'manual'
      Array(params[:exploit_ids]).map(&:to_i).select { |id| id > 0 }
    end

    if exploit_ids.empty?
      redirect_to scanner_path, alert: "No exploits selected."
      return
    end

    scan_options = {
      port_override:    params[:port_override].presence,
      payload_override: params[:payload_override].presence,
      timeout:          params[:timeout].presence&.to_i
    }.compact

    ScanJob.perform_later(org_id, exploit_ids, Current.user.id, asset_ids, scan_options)
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

  private

  def auto_select_exploits(os_list)
    return Exploit.pluck(:id) if os_list.empty?
    os_patterns = os_list.flat_map { |os|
      case os
      when 'linux'   then ['linux', 'unix']
      when 'windows' then ['windows', 'smb', 'ms1', 'ms0', 'rdp']
      when 'macos'   then ['macos', 'osx', 'apple']
      else []
      end
    }.uniq
    return Exploit.pluck(:id) if os_patterns.empty?
    Exploit.where(
      os_patterns.map { "metasploit_module ILIKE ?" }.join(" OR "),
      *os_patterns.map { |p| "%#{p}%" }
    ).pluck(:id)
  end
end
