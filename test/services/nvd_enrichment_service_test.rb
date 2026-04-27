require "test_helper"

class NvdEnrichmentServiceTest < ActiveSupport::TestCase
  def setup
    @exploit = exploits(:exploit_one)
    @exploit.update_columns(cvss_score: nil, cvss_vector: nil, cwe_id: nil)
  end

  def nvd_response(score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cwe: "CWE-119")
    {
      "vulnerabilities" => [{
        "cve" => {
          "metrics" => {
            "cvssMetricV31" => [{
              "cvssData" => {
                "baseScore"    => score,
                "vectorString" => vector
              }
            }]
          },
          "weaknesses" => [{
            "description" => [{ "value" => cwe }]
          }]
        }
      }]
    }.to_json
  end

  def stub_http_success(body)
    response = Object.new
    response.define_singleton_method(:is_a?) { |klass| klass == Net::HTTPSuccess }
    response.define_singleton_method(:body)  { body }
    Net::HTTP.stub(:get_response, response) { yield }
  end

  def stub_http_failure
    response = Object.new
    response.define_singleton_method(:is_a?) { |_| false }
    Net::HTTP.stub(:get_response, response) { yield }
  end

  # ── skips when no CVE ────────────────────────────────────────────────────────

  test "enrich skips exploit with no cve_id" do
    @exploit.update_columns(cve_id: nil)
    NvdEnrichmentService.enrich(@exploit)
    assert_nil @exploit.reload.cvss_score
  end

  test "enrich skips exploit that already has a cvss_score" do
    @exploit.update_columns(cvss_score: 7.5)
    NvdEnrichmentService.enrich(@exploit)
    assert_equal 7.5, @exploit.reload.cvss_score
  end

  # ── successful enrichment ─────────────────────────────────────────────────────

  test "enrich sets cvss_score from NVD response" do
    stub_http_success(nvd_response(score: 9.8)) do
      NvdEnrichmentService.enrich(@exploit)
    end
    assert_equal 9.8, @exploit.reload.cvss_score
  end

  test "enrich sets cvss_vector from NVD response" do
    stub_http_success(nvd_response) do
      NvdEnrichmentService.enrich(@exploit)
    end
    assert_not_nil @exploit.reload.cvss_vector
  end

  test "enrich sets cwe_id when it starts with CWE-" do
    stub_http_success(nvd_response(cwe: "CWE-119")) do
      NvdEnrichmentService.enrich(@exploit)
    end
    assert_equal "CWE-119", @exploit.reload.cwe_id
  end

  test "enrich ignores cwe_id that does not start with CWE-" do
    stub_http_success(nvd_response(cwe: "NVD-CWE-noinfo")) do
      NvdEnrichmentService.enrich(@exploit)
    end
    assert_nil @exploit.reload.cwe_id
  end

  # ── failed HTTP response ──────────────────────────────────────────────────────

  test "enrich does nothing on non-success HTTP response" do
    stub_http_failure do
      NvdEnrichmentService.enrich(@exploit)
    end
    assert_nil @exploit.reload.cvss_score
  end

  # ── network error ─────────────────────────────────────────────────────────────

  test "enrich swallows network errors and logs a warning" do
    Net::HTTP.stub(:get_response, ->(_uri) { raise "timeout" }) do
      assert_nothing_raised { NvdEnrichmentService.enrich(@exploit) }
    end
    assert_nil @exploit.reload.cvss_score
  end
end
