module Api
  class ReportsApiController < ApiController
    before_action :require_api_admin!, only: [:retest]

    def index
      render json: { reports: org_reports.order(generated_at: :desc).map { |r| report_json(r) } }
    end

    def show
      report = org_reports.find(params[:id])
      render json: { report: report_json(report) }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def destroy
      report = org_reports.find(params[:id])
      report.destroy
      render json: { deleted: true, id: params[:id].to_i }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def download_json
      report = org_reports.find(params[:id])
      send_data report.report_data.to_json,
        filename:    "#{report.report_name.parameterize}.json",
        type:        "application/json",
        disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def download_xlsx
      report = org_reports.find(params[:id])
      xlsx = ScanReportXlsx.new(report)
      send_data xlsx.render,
        filename:    "#{report.report_name.parameterize}.xlsx",
        type:        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def download_csv
      report = org_reports.find(params[:id])
      csv = ScanReportCsv.new(report)
      send_data csv.render,
        filename:    "#{report.report_name.parameterize}.csv",
        type:        "text/csv",
        disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def download_whitebox_json
      report = org_reports.find(params[:id])
      unless report.whitebox?
        render json: { error: "Not a whitebox report" }, status: :unprocessable_entity
        return
      end

      findings = Array(report.report_data)
        .select { |r| r["isVulnerable"] == true || r[:isVulnerable] == true }
        .map do |r|
          {
            target:       r["target"]       || r[:target],
            port:         r["port"]         || r[:port],
            isVulnerable: true,
            exploit:      r["exploit"]      || r[:exploit],
            exploit_name: r["exploit_name"] || r[:exploit_name],
            severity:     r["severity"]     || r[:severity],
            cve_id:       r["cve_id"]       || r[:cve_id],
            evidence:     r["evidence"]     || r[:evidence],
            exploit_code: r["exploit_code"] || r[:exploit_code]
          }
        end

      payload = {
        report_name:  report.report_name,
        scan_type:    "whitebox",
        generated_at: report.generated_at,
        findings:     findings
      }
      send_data payload.to_json,
        filename:    "#{report.report_name.parameterize}-whitebox.json",
        type:        "application/json",
        disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def data
      report = org_reports.find(params[:id])
      render json: { report_data: report.report_data }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def retest
      report   = org_reports.includes(:scan).find(params[:id])
      scan     = report.scan
      findings = Finding.where(scan_id: report.scan_id).includes(:exploit, :asset)

      asset_ids        = findings.map(&:asset_id).uniq.compact
      module_allowlist = findings.map { |f| f.exploit&.metasploit_module }.uniq.compact

      if asset_ids.empty? || module_allowlist.empty?
        render json: { error: "No findings to retest" }, status: :unprocessable_entity
        return
      end

      filter_params = { "module_allowlist" => module_allowlist }
      scan_options  = { safe_mode: scan&.safe_mode?, retest_of: scan&.id }

      ScanJob.perform_later(@current_user.organization_id, filter_params,
                            @current_user.id, asset_ids, scan_options)
      render json: {
        queued:       true,
        asset_count:  asset_ids.size,
        module_count: module_allowlist.size
      }, status: :accepted
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    private

    def org_reports
      Report.where(user_id: User.where(organization_id: @current_user.organization_id).select(:id))
    end

    def report_json(r)
      {
        id:           r.id,
        report_name:  r.report_name,
        report_type:  r.report_type,
        report_format: r.report_format,
        scan_id:      r.scan_id,
        generated_at: r.generated_at,
        generated_by: r.generated_by
      }
    end
  end
end
