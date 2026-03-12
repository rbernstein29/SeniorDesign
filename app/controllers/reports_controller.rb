class ReportsController < ApplicationController

  def destroy
    report = Report.find(params[:id])
    report.destroy
    redirect_to reports_path, notice: 'Report deleted.'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

  def download_pdf
    report = Report.find(params[:id])
    pdf = ScanReportPdf.new(report)
    send_data pdf.render,
      filename:    "#{report.report_name.parameterize}.pdf",
      type:        'application/pdf',
      disposition: 'attachment'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end

end
