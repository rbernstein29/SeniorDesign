require 'net/http'
require 'json'

class NvdEnrichmentService
  NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

  def self.enrich(exploit)
    return if exploit.cve_id.blank? || exploit.cvss_score.present?

    uri      = URI("#{NVD_URL}?cveId=#{exploit.cve_id}")
    response = Net::HTTP.get_response(uri)
    return unless response.is_a?(Net::HTTPSuccess)

    data = JSON.parse(response.body)
    vuln = data.dig('vulnerabilities', 0, 'cve')
    return unless vuln

    metrics = vuln.dig('metrics', 'cvssMetricV31', 0) ||
              vuln.dig('metrics', 'cvssMetricV30', 0) ||
              vuln.dig('metrics', 'cvssMetricV2', 0)
    cwe = vuln.dig('weaknesses', 0, 'description', 0, 'value')

    exploit.update_columns(
      cvss_score:  metrics&.dig('cvssData', 'baseScore'),
      cvss_vector: metrics&.dig('cvssData', 'vectorString')&.first(100),
      cwe_id:      (cwe&.start_with?('CWE-') ? cwe : nil)
    )
  rescue => e
    Rails.logger.warn("NVD enrichment failed for #{exploit.cve_id}: #{e.message}")
  end
end
