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
      csv << ["Target", "Port", "Exploit", "Status", "Time"]
      results.each do |r|
        status = r[:success] ? "VULNERABLE" : "Secure"
        time = (Time.parse(r[:timestamp].to_s).strftime("%H:%M:%S") rescue r[:timestamp].to_s)
        csv << [r[:target], r[:port].to_s, r[:exploit], status, time]
      end
    end
  end
end
