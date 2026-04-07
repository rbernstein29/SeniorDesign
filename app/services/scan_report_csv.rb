require "csv"

class ScanReportCsv
  def initialize(report)
    @report = report
  end

  def render
    raw = @report.report_data || []
    raw = JSON.parse(raw) if raw.is_a?(String)
    results = raw.map { |r| r.is_a?(Hash) ? r.with_indifferent_access : {} }

    CSV.generate do |csv|
      csv << ["Target", "Port", "Exploit Module", "Exploit Name", "CVE ID", "Severity", "Description", "Disclosure Date", "References", "Status", "Evidence", "Time"]
      results.each do |r|
        status = r[:success] ? "VULNERABLE" : "Secure"
        time   = (Time.parse(r[:timestamp].to_s).strftime("%H:%M:%S") rescue r[:timestamp].to_s)
        refs   = Array(r[:references]).map { |ref| "#{ref['type']}: #{ref['value']}" }.join(" | ")
        csv << [
          r[:target],
          r[:port].to_s,
          r[:exploit],
          r[:exploit_name],
          r[:cve_id],
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
end
