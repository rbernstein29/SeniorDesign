module Api
  class ScansApiController < ApiController
    before_action :require_api_admin!, only: [:trigger, :stop]

    def index
      org_scans = Scan.for_org(@current_user.organization_id).order(created_at: :desc)
      render json: {
        stats: {
          total:     org_scans.count,
          running:   org_scans.running.count,
          completed: org_scans.completed.count,
          failed:    org_scans.failed.count
        },
        scans: org_scans.map { |s| scan_json(s) }
      }
    end

    def show
      scan = Scan.for_org(@current_user.organization_id).find(params[:id])
      render json: { scan: scan_json(scan) }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Scan not found" }, status: :not_found
    end

    # POST /api/:key/scans/trigger
    # Body: asset_ids[] (required), profile_id, safe_mode, platform, severities[],
    #       port_override, timeout, use_agent
    def trigger
      org_id    = @current_user.organization_id
      asset_ids = Array(params[:asset_ids]).map(&:to_i).select { |id| id > 0 }

      if asset_ids.empty?
        render json: { error: "No targets selected" }, status: :unprocessable_entity
        return
      end

      valid_ids = Asset.where(organization_id: org_id, id: asset_ids).pluck(:id)
      if valid_ids.empty?
        render json: { error: "No valid assets found in your organization" }, status: :unprocessable_entity
        return
      end

      filter_params = {
        platform:   params[:platform].presence || "any",
        severities: Array(params[:severities]).presence
      }.compact

      if params[:profile_id].present?
        profile = ScanProfile.find_by(id: params[:profile_id], organization_id: org_id)
        if profile&.exploit_ids&.any?
          allowlist = Exploit.where(id: profile.exploit_ids).pluck(:metasploit_module).compact
          filter_params[:module_allowlist] = allowlist if allowlist.any?
        end
      end

      safe_mode    = params[:safe_mode].to_s == "true"
      scan_options = {
        port_override: params[:port_override].presence,
        timeout:       params[:timeout].presence&.to_i,
        use_agent:     params[:use_agent].to_s == "true",
        safe_mode:     safe_mode
      }.compact

      ScanJob.perform_later(org_id, filter_params, @current_user.id, valid_ids, scan_options)
      render json: { queued: true, asset_count: valid_ids.size }, status: :accepted
    end

    # POST /api/:key/scans/stop
    # Body: scan_id
    def stop
      scan = Scan.for_org(@current_user.organization_id).running.find_by(id: params[:scan_id])
      if scan
        scan.update!(status: "cancelled", end_time: Time.current)
        render json: { stopped: true, scan_id: scan.id }
      else
        render json: { error: "Running scan not found" }, status: :not_found
      end
    end

    private

    def scan_json(s)
      report = s.reports.first
      {
        id:                    s.id,
        scan_name:             s.scan_name,
        status:                s.status,
        safe_mode:             s.safe_mode,
        is_retest:             s.is_retest,
        retest_of:             s.retest_of,
        total_assets:          s.total_assets,
        scanned_assets:        s.scanned_assets,
        total_exploits_tested: s.total_exploits_tested,
        findings_count:        s.findings_count,
        critical_findings:     s.critical_findings,
        high_findings:         s.high_findings,
        medium_findings:       s.medium_findings,
        low_findings:          s.low_findings,
        start_time:            s.start_time,
        end_time:              s.end_time,
        report_id:             report&.id
      }
    end
  end
end
