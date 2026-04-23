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
    safe = @report.report_type == 'reconnaissance'

    detected_count   = results.count { |r| r[:success] }
    undetected_count = results.size - detected_count

    wb.add_worksheet(name: "Summary") do |sheet|
      if safe
        sheet.add_row ["Safe Mode Scan Report"], b: true
        sheet.add_row []
        sheet.add_row ["Report ID",      "##{@report.id}"]
        sheet.add_row ["Generated At",   @report.generated_at&.strftime("%Y-%m-%d %H:%M:%S")]
        sheet.add_row ["Organization ID", @report.organization_id]
        sheet.add_row ["Initiated By",   @report.user&.email_address || "Unknown"]
        sheet.add_row []
        sheet.add_row ["Total Modules Run", results.size]
        sheet.add_row ["Detected",          detected_count]
        sheet.add_row ["Not Detected",      undetected_count]
      else
        vulnerable_count = detected_count
        secure_count     = undetected_count
        sheet.add_row ["Exploit Scan Report"], b: true
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
    end

    wb.add_worksheet(name: "Findings") do |sheet|
      if safe
        sheet.add_row ["Target", "Port", "Module", "Detected", "Evidence", "Time"], b: true
        results.each do |r|
          time = (Time.parse(r[:timestamp].to_s).strftime("%H:%M:%S") rescue r[:timestamp].to_s)
          sheet.add_row [
            r[:target],
            r[:port].to_s,
            r[:exploit_name].presence || r[:exploit],
            r[:success] ? "Yes" : "No",
            r[:evidence],
            time
          ]
        end
      else
        sheet.add_row ["Target", "Port", "Exploit Module", "Exploit Name", "CVE ID", "CVSS Score",
                       "CWE", "Severity", "Description", "Disclosure Date", "References",
                       "Status", "Evidence", "Time"], b: true
        results.each do |r|
          status = r[:success] ? "VULNERABLE" : "Secure"
          time   = (Time.parse(r[:timestamp].to_s).strftime("%H:%M:%S") rescue r[:timestamp].to_s)
          refs   = Array(r[:references]).map { |ref| "#{ref['type']}: #{ref['value']}" }.join(" | ")
          exploit_record = Exploit.find_by(exploit_id: r[:exploit])
          sheet.add_row [
            r[:target],
            r[:port].to_s,
            r[:exploit],
            r[:exploit_name],
            r[:cve_id],
            exploit_record&.cvss_score,
            exploit_record&.cwe_id,
            r[:severity],
            r[:description],
            r[:disclosure_date],
            refs,
            status,
            r[:evidence],
            time
          ]
        end
      end
    end

    package.to_stream.read
  end
end
