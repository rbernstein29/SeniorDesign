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

  def home_stats
    org_id       = current_org_id
    agents       = Agent.where(organization_id: org_id)
    assets       = Asset.where(organization_id: org_id)
    org_user_ids = User.where(organization_id: org_id).select(:id)
    reports      = Report.where(user_id: org_user_ids)
    connected    = agents.count(&:connected?)
    total_agents = agents.count
    last_scan_at = reports.maximum(:generated_at)

    activity = []
    begin
      Scan.for_org(org_id).order(created_at: :desc).limit(5).each do |s|
        color = s.status == 'completed' ? 'green' : s.status == 'failed' ? 'red' : 'cyan'
        activity << {
          color: color,
          text:  "Scan <strong>#{ERB::Util.h(s.scan_name)}</strong> #{ERB::Util.h(s.status)}",
          time:  s.start_time ? "#{time_ago_in_words(s.start_time)} ago" : '—'
        }
      end
      last_agent = agents.order(last_seen: :desc).first
      if last_agent&.last_seen
        activity << {
          color: last_agent.connected? ? 'green' : 'orange',
          text:  "Agent <strong>#{ERB::Util.h(last_agent.agent_id.first(8))}&hellip;</strong> last heartbeat",
          time:  "#{time_ago_in_words(last_agent.last_seen)} ago"
        }
      end
      last_session = Session.joins(:user).where(users: { organization_id: org_id }).order(created_at: :desc).first
      if last_session
        activity << {
          color: 'blue',
          text:  "User <strong>#{ERB::Util.h(last_session.user.name)}</strong> signed in",
          time:  "#{time_ago_in_words(last_session.created_at)} ago"
        }
      end
    rescue => e
      Rails.logger.warn "home_stats activity error: #{e.message}"
    end

    render json: {
      stats: {
        offline_agents:    total_agents - connected,
        total_agents:      total_agents,
        connected_agents:  connected,
        active_scans:      Scan.for_org(org_id).running.count,
        last_scan:         last_scan_at ? "#{time_ago_in_words(last_scan_at)} ago" : 'Never',
        total_assets:      assets.count,
        scan_ready_assets: assets.where.not(scan_config: [nil, '']).count,
        total_sites:       Site.where(organization_id: org_id).count,
        users_count:       User.where(organization_id: org_id).count,
        total_reports:     reports.count
      },
      activity: activity
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
    scan&.update!(status: 'cancelled', end_time: Time.current)
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

end
