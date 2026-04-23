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

    # Lazily enrich up to 10 unenriched CVEs from NVD (free tier: 5 req/30s)
    unenriched = @findings.map(&:exploit).compact.uniq
                          .select { |e| e.cve_id.present? && e.cvss_score.nil? }
                          .first(10)
    unenriched.each_with_index do |exploit, i|
      NvdEnrichmentService.enrich(exploit)
      sleep(0.25) if i < unenriched.size - 1
    end

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
    scan   = report.scan

    findings         = Finding.where(scan_id: report.scan_id).includes(:exploit, :asset)
    asset_ids        = findings.map(&:asset_id).uniq.compact
    module_allowlist = findings.map { |f| f.exploit&.metasploit_module }.uniq.compact

    if asset_ids.empty? || module_allowlist.empty?
      redirect_to report_path(report), alert: 'No findings to retest.'
      return
    end

    filter_params = { 'module_allowlist' => module_allowlist }
    scan_options  = { safe_mode: scan&.safe_mode?, retest_of: scan&.id }

    ScanJob.perform_later(current_org_id, filter_params, Current.user.id, asset_ids, scan_options)
    redirect_to scans_path,
      notice: "Retest queued — #{asset_ids.size} asset(s), #{module_allowlist.size} module(s)."

  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found.'
  end

  def destroy
    report = org_reports.find(params[:id])
    report.destroy
    redirect_to reports_path, notice: 'Report deleted.'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def download_json
    report = org_reports.find(params[:id])
    send_data report.report_data.to_json,
      filename:    "#{report.report_name.parameterize}.json",
      type:        'application/json',
      disposition: 'attachment'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def download_xlsx
    report = org_reports.find(params[:id])
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
