# Builds the JSON payload returned by the whitebox-report download endpoint.
module Aegis
  module Reports
    class WhiteboxPayload
      def initialize(report)
        @report = report
      end

      def to_h
        {
          report_name:  @report.report_name,
          scan_type:    'whitebox',
          generated_at: @report.generated_at,
          findings:     vulnerable_findings
        }
      end

      def to_json(*)
        to_h.to_json
      end

      private

      def vulnerable_findings
        Array(@report.report_data)
          .select { |r| r['isVulnerable'] == true || r[:isVulnerable] == true }
          .map { |r| project(r) }
      end

      def project(r)
        {
          target:       r['target']       || r[:target],
          port:         r['port']         || r[:port],
          isVulnerable: true,
          exploit:      r['exploit']      || r[:exploit],
          exploit_name: r['exploit_name'] || r[:exploit_name],
          severity:     r['severity']     || r[:severity],
          cve_id:       r['cve_id']       || r[:cve_id],
          evidence:     r['evidence']     || r[:evidence],
          exploit_code: r['exploit_code'] || r[:exploit_code]
        }
      end
    end
  end
end
