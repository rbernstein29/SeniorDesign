require "caxlsx"

class ScanReportXlsx
  def initialize(report)
    @report = report
  end

  def render
    package    = Axlsx::Package.new
    wb         = package.workbook
    serializer = Aegis::ReportRowSerializer.new(@report)
    results    = serializer.results

    detected_count   = results.count { |r| r[:success] }
    undetected_count = results.size - detected_count

    wb.add_worksheet(name: "Summary") { |sheet| add_summary_rows(sheet, results, detected_count, undetected_count, serializer.safe?) }

    wb.add_worksheet(name: "Findings") do |sheet|
      sheet.add_row serializer.headers, b: true
      serializer.rows.each { |row| sheet.add_row row }
    end

    package.to_stream.read
  end

  private

  def add_summary_rows(sheet, results, detected_count, undetected_count, safe)
    title = safe ? "Safe Mode Scan Report" : "Exploit Scan Report"
    sheet.add_row [title], b: true
    sheet.add_row []
    sheet.add_row ["Report ID",       "##{@report.id}"]
    sheet.add_row ["Generated At",    @report.generated_at&.strftime("%Y-%m-%d %H:%M:%S")]
    sheet.add_row ["Organization ID", @report.organization_id]
    sheet.add_row ["Initiated By",    @report.user&.email_address || "Unknown"]
    sheet.add_row []

    if safe
      sheet.add_row ["Total Modules Run", results.size]
      sheet.add_row ["Detected",          detected_count]
      sheet.add_row ["Not Detected",      undetected_count]
    else
      sheet.add_row ["Total Results", results.size]
      sheet.add_row ["Vulnerable",    detected_count]
      sheet.add_row ["Secure",        undetected_count]
    end
  end
end
