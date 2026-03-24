require "caxlsx"

class ScanReportXlsx
  def initialize(report)
    @report = report
  end

  def render
    package = Axlsx::Package.new
    wb = package.workbook

    raw = @report.report_data || []
    raw = JSON.parse(raw) if raw.is_a?(String)
    results = raw.map { |r| r.is_a?(Hash) ? r.with_indifferent_access : {} }
    vulnerable_count = results.count { |r| r[:success] }
    secure_count = results.size - vulnerable_count

    wb.add_worksheet(name: "Summary") do |sheet|
      sheet.add_row ["Vulnerability Scan Report"], b: true
      sheet.add_row []
      sheet.add_row ["Report ID",      "##{@report.id}"]
      sheet.add_row ["Generated At",   @report.generated_at&.strftime("%Y-%m-%d %H:%M:%S")]
      sheet.add_row ["Organization ID", @report.organization_id]
      sheet.add_row ["Initiated By",   @report.user&.email_address || "Unknown"]
      sheet.add_row []
      sheet.add_row ["Total Results",  results.size]
      sheet.add_row ["Vulnerable",     vulnerable_count]
      sheet.add_row ["Secure",         secure_count]
    end

    wb.add_worksheet(name: "Findings") do |sheet|
      sheet.add_row ["Target", "Port", "Exploit", "Status", "Time"], b: true
      results.each do |r|
        status = r[:success] ? "VULNERABLE" : "Secure"
        time = (Time.parse(r[:timestamp].to_s).strftime("%H:%M:%S") rescue r[:timestamp].to_s)
        sheet.add_row [r[:target], r[:port].to_s, r[:exploit], status, time]
      end
    end

    package.to_stream.read
  end
end
