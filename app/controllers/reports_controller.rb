class ReportsController < ApplicationController

  def show
    @report = org_reports.includes(:scan).find(params[:id])
    @scan   = @report.scan

    severity_order = Arel.sql(
      "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
    )
    @findings = Finding.where(scan_id: @report.scan_id)
                       .includes(:exploit, :asset)
                       .order(severity_order, :discovered_at)

    # Enrich unenriched CVEs in the background so the page loads immediately.
    unenriched_ids = @findings.map(&:exploit).compact.uniq
                              .select { |e| e.cve_id.present? && e.cvss_score.nil? }
                              .first(Aegis.config.nvd.max_per_request)
                              .map(&:id)
    NvdEnrichmentJob.perform_later(unenriched_ids) if unenriched_ids.any?

    # Scan-over-scan comparison
    @prev_scan             = nil
    @new_finding_ids       = Set.new
    @recurring_finding_ids = Set.new
    @remediated_count      = 0

    if @scan
      @prev_scan = Scan.where(organization_id: current_org_id, safe_mode: @scan.safe_mode?)
                       .where('id < ?', @scan.id)
                       .where(status: 'completed')
                       .order(id: :desc)
                       .first

      if @prev_scan
        prev_pairs = Finding.where(scan_id: @prev_scan.id)
                            .pluck(:asset_id, :exploit_id)
                            .to_set
        curr_pairs = @findings.map { |f| [f.asset_id, f.exploit_id] }.to_set

        @findings.each do |f|
          if prev_pairs.include?([f.asset_id, f.exploit_id])
            @recurring_finding_ids << f.id
          else
            @new_finding_ids << f.id
          end
        end

        @remediated_count = prev_pairs.count { |pair| !curr_pairs.include?(pair) }
      end
    end

    @findings_by_asset = @findings.group_by(&:asset)

  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found.'
  end

  def retest
    report = org_reports.includes(:scan).find(params[:id])
    result = Aegis::Reports::Retester.new(report, organization_id: current_org_id, user_id: Current.user.id).call

    if result.queued?
      redirect_to scans_path,
        notice: "Retest queued — #{result.asset_count} asset(s), #{result.module_count} module(s)."
    else
      redirect_to report_path(report), alert: "#{result.error}."
    end
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found.'
  end

  def destroy
    report = org_reports.find(params[:id])
    log_activity(text: "Report <strong>#{ERB::Util.h(report.report_name)}</strong> deleted", color: 'red')
    report.destroy
    redirect_to reports_path, notice: 'Report deleted.'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def download_json
    report = org_reports.find(params[:id])
    log_activity(text: "Report <strong>#{ERB::Util.h(report.report_name)}</strong> downloaded (JSON)", color: 'violet')
    send_data report.report_data.to_json,
      filename:    "#{report.report_name.parameterize}.json",
      type:        'application/json',
      disposition: 'attachment'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def download_whitebox_json
    report = org_reports.find(params[:id])
    log_activity(text: "Report <strong>#{ERB::Util.h(report.report_name)}</strong> downloaded (Whitebox JSON)", color: 'violet')
    unless report.whitebox?
      redirect_to report_path(report), alert: 'This report is not a whitebox report.'
      return
    end

    send_data Aegis::Reports::WhiteboxPayload.new(report).to_json,
      filename:    "#{report.report_name.parameterize}-whitebox.json",
      type:        'application/json',
      disposition: 'attachment'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def download_xlsx
    report = org_reports.find(params[:id])
    log_activity(text: "Report <strong>#{ERB::Util.h(report.report_name)}</strong> downloaded (XLSX)", color: 'violet')
    xlsx = ScanReportXlsx.new(report)
    send_data xlsx.render,
      filename:    "#{report.report_name.parameterize}.xlsx",
      type:        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      disposition: 'attachment'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def download_csv
    report = org_reports.find(params[:id])
    log_activity(text: "Report <strong>#{ERB::Util.h(report.report_name)}</strong> downloaded (CSV)", color: 'violet')
    csv = ScanReportCsv.new(report)
    send_data csv.render,
      filename:    "#{report.report_name.parameterize}.csv",
      type:        'text/csv',
      disposition: 'attachment'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def data
    report = org_reports.find(params[:id])
    render json: { report_data: report.report_data }
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'Not found' }, status: :not_found
  end

  private

  def org_reports
    Report.where(user_id: User.where(organization_id: current_org_id).select(:id))
  end

end
