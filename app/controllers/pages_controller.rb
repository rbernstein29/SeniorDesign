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

    @recent_activity = build_activity_events(org_id)
  end

  def home_recent_findings
    org_id = current_org_id
    @recent_findings = Finding.where(
      scan_id: Scan.for_org(org_id).select(:id)
    ).includes(:exploit, :asset).order(discovered_at: :desc).limit(10) rescue []
    render partial: 'recent_findings', locals: { recent_findings: @recent_findings }
  end

  def home_stats
    org_id       = current_org_id
    agents       = Agent.where(organization_id: org_id)
    assets       = Asset.where(organization_id: org_id)
    org_user_ids = User.where(organization_id: org_id).select(:id)
    reports      = Report.where(user_id: org_user_ids)
    connected    = agents.count(&:connected?)
    total_agents = agents.count
    last_scan_at = reports.maximum(:generated_at)

    active_count = Scan.for_org(org_id).running.count
    scan_ready   = assets.where.not(scan_config: [nil, '']).count

    render json: {
      stats: {
        offline_agents:    total_agents - connected,
        total_agents:      total_agents,
        connected_agents:  connected,
        active_scans:      active_count,
        last_scan:         last_scan_at ? "#{helpers.time_ago_in_words(last_scan_at)} ago" : 'Never',
        total_assets:      assets.count,
        scan_ready_assets: scan_ready,
        total_sites:       Site.where(organization_id: org_id).count,
        users_count:       User.where(organization_id: org_id).count,
        total_reports:     reports.count
      },
      stat_deltas: {
        offline_agents:   (total_agents - connected) > 0 ? 'Not reachable' : 'All online',
        connected_agents: connected > 0 ? 'Online now' : 'None online',
        active_scans:     active_count > 0 ? 'Currently running' : 'No scans running',
        scan_ready_assets: scan_ready > 0 ? 'With scan config' : 'No scan config set'
      },
      activity: build_activity_events_json(org_id)
    }
  end

  def scanner
    org_id    = Current.user.organization_id
    @assets   = Asset.where(organization_id: org_id).includes(:site).order(:ip_address)
    @sites    = Site.where(organization_id: org_id)
    @profiles = ScanProfile.where(organization_id: org_id)
  end

  def trigger_scan
    org_id = Current.user.organization_id

    # Resolve target asset IDs from checkboxes (all target modes submit asset_ids[])
    asset_ids = Array(params[:asset_ids]).map(&:to_i).select { |id| id > 0 }

    if asset_ids.empty?
      redirect_to scanner_path, alert: "No targets selected."
      return
    end

    filter_params = {
      platform:   params[:platform].presence || 'any',
      severities: Array(params[:severities]).presence
    }.compact

    profile = nil
    if params[:profile_id].present?
      profile = ScanProfile.find_by(id: params[:profile_id], organization_id: org_id)
      if profile&.exploit_ids&.any?
        allowlist = Exploit.where(id: profile.exploit_ids).pluck(:metasploit_module).compact
        filter_params[:module_allowlist] = allowlist if allowlist.any?
      end
    end

    safe_mode = params[:safe_mode] == 'true' || profile&.safe_mode? || false
    scan_options = {
      port_override: params[:port_override].presence,
      timeout:       params[:timeout].presence&.to_i,
      use_agent:     params[:use_agent] == 'true',
      safe_mode:     safe_mode
    }.compact

    log_activity(text: "Scan queued for <strong>#{asset_ids.size}</strong> target(s)", color: 'cyan')
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

  def scans_status
    org_scans = Scan.for_org(current_org_id)
    ids       = Array(params[:ids]).map(&:to_i).select { |id| id > 0 }
    scans     = ids.any? ? org_scans.where(id: ids) : org_scans.none
    render json: {
      stats: {
        total:     org_scans.count,
        running:   org_scans.running.count,
        completed: org_scans.completed.count,
        failed:    org_scans.failed.count
      },
      scans: scans.map { |s|
        report = s.reports.first
        {
          id:                    s.id,
          status:                s.status,
          scanned_assets:        s.scanned_assets,
          total_assets:          s.total_assets,
          total_exploits_tested: s.total_exploits_tested,
          findings_count:        s.findings_count,
          report_id:             report&.id
        }
      }
    }
  end

  def stop_scan
    scan = Scan.for_org(current_org_id).running.find_by(id: params[:scan_id])
    if scan
      scan.update!(status: 'cancelled', end_time: Time.current)
      log_activity(text: "Scan <strong>#{ERB::Util.h(scan.scan_name)}</strong> stopped", color: 'orange')
    end
    redirect_to scans_path, notice: "Scan stopped."
  end

  def reports
    @reports = Report.where(user_id: User.where(organization_id: current_org_id).select(:id))
                     .includes(:scan)
                     .order(generated_at: :desc)
    scan_ids = @reports.map(&:scan_id).compact
    scans = Scan.where(id: scan_ids)
    @critical_findings   = scans.sum(:critical_findings)
    @high_findings       = scans.sum(:high_findings)
    @medium_low_findings = scans.sum(:medium_findings) + scans.sum(:low_findings)
  end

  def settings
    @org = Organization.find_by(id: Current.session.user.organization_id)
  rescue
    @org = nil
  end

  def api_docs
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

  def build_activity_events(org_id)
    ActivityLog.for_org(org_id).order(created_at: :desc).limit(ActivityLog::LIMIT_PER_ORG).to_a
  end

  def build_activity_events_json(org_id)
    ActivityLog.for_org(org_id).order(created_at: :desc).limit(ActivityLog::LIMIT_PER_ORG).map do |l|
      { color: l.color, text: l.text, time: "#{helpers.time_ago_in_words(l.created_at)} ago" }
    end
  end

end
