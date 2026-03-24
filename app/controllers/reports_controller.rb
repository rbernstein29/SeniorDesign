class ReportsController < ApplicationController

  def destroy
    report = org_reports.find(params[:id])
    report.destroy
    redirect_to reports_path, notice: 'Report deleted.'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def download_pdf
    report = org_reports.find(params[:id])
    pdf = ScanReportPdf.new(report)
    send_data pdf.render,
      filename:    "#{report.report_name.parameterize}.pdf",
      type:        'application/pdf',
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

  private

  def org_reports
    Report.where(user_id: User.where(organization_id: current_org_id).select(:id))
  end

end
