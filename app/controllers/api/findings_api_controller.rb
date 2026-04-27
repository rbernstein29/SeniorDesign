module Api
  class FindingsApiController < ApiController

    # GET /api/:key/findings
    # Optional filters: ?scan_id=, ?severity=critical|high|medium|low, ?status=open
    def index
      findings = Finding.for_org(@current_user.organization_id)
                        .includes(:exploit, :asset)
                        .order(discovered_at: :desc)
      findings = findings.where(scan_id: params[:scan_id]) if params[:scan_id].present?
      findings = findings.where(severity:  params[:severity]) if params[:severity].present?
      findings = findings.where(status:    params[:status])   if params[:status].present?
      render json: { findings: findings.map { |f| finding_json(f) } }
    end

    def show
      finding = Finding.for_org(@current_user.organization_id)
                       .includes(:exploit, :asset)
                       .find(params[:id])
      render json: { finding: finding_json(finding) }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Finding not found" }, status: :not_found
    end

    def ai_remediation
      finding = Finding.for_org(@current_user.organization_id)
                       .includes(:exploit)
                       .find(params[:id])
      if finding.ai_remediation.blank?
        text = OllamaService.remediation_for(finding.exploit, finding)
        finding.update_column(:ai_remediation, text)
      end
      render json: { text: finding.ai_remediation }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Finding not found" }, status: :not_found
    end

    private

    def finding_json(f)
      {
        id:             f.id,
        scan_id:        f.scan_id,
        asset_id:       f.asset_id,
        asset_ip:       f.asset&.ip_address.to_s,
        exploit_id:     f.exploit_id,
        exploit_name:   f.exploit&.name,
        cve_id:         f.exploit&.cve_id,
        severity:       f.severity,
        status:         f.status,
        confidence:     f.confidence,
        port:           f.port,
        evidence:       f.evidence,
        ai_remediation: f.ai_remediation,
        discovered_at:  f.discovered_at,
        remediated_at:  f.remediated_at
      }
    end
  end
end
