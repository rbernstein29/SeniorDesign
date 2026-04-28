# Normalizes a Report's report_data into header + row arrays for export.
# Both ScanReportCsv and ScanReportXlsx render from these.
#
# Centralizes the safe-mode-vs-vulnerability-mode column choice, the time
# formatting, the references join, and the per-exploit DB lookup so the two
# renderers can't drift apart.
module Aegis
  class ReportRowSerializer
    HEADERS_RECON = ["Target", "Port", "Module", "Detected", "Evidence", "Time"].freeze

    HEADERS_VULN  = [
      "Target", "Port", "Exploit Module", "Exploit Name", "CVE ID", "CVSS Score",
      "CWE", "Severity", "Description", "Disclosure Date", "References",
      "Status", "Evidence", "Time"
    ].freeze

    def initialize(report)
      @report = report
    end

    def safe?
      @report.report_type == 'reconnaissance'
    end

    def headers
      safe? ? HEADERS_RECON : HEADERS_VULN
    end

    def rows
      results.map { |r| safe? ? recon_row(r) : vuln_row(r) }
    end

    def results
      @results ||= begin
        raw = @report.report_data || []
        raw = JSON.parse(raw) if raw.is_a?(String)
        raw.map { |r| r.is_a?(Hash) ? r.with_indifferent_access : {} }
      end
    end

    private

    def recon_row(r)
      [
        r[:target],
        r[:port].to_s,
        r[:exploit_name].presence || r[:exploit],
        r[:success] ? "Yes" : "No",
        r[:evidence],
        format_time(r[:timestamp])
      ]
    end

    def vuln_row(r)
      exploit = exploit_for(r[:exploit])
      refs    = Array(r[:references]).map { |ref| "#{ref['type']}: #{ref['value']}" }.join(" | ")
      [
        r[:target],
        r[:port].to_s,
        r[:exploit],
        r[:exploit_name],
        r[:cve_id],
        exploit&.cvss_score,
        exploit&.cwe_id,
        r[:severity],
        r[:description],
        r[:disclosure_date],
        refs,
        r[:success] ? "VULNERABLE" : "Secure",
        r[:evidence],
        format_time(r[:timestamp])
      ]
    end

    def exploit_for(exploit_id)
      return nil if exploit_id.blank?
      @exploit_cache ||= {}
      @exploit_cache[exploit_id] ||= Exploit.find_by(exploit_id: exploit_id)
    end

    def format_time(value)
      Time.parse(value.to_s).strftime("%H:%M:%S")
    rescue
      value.to_s
    end
  end
end
