require "test_helper"

class Aegis::Reports::WhiteboxPayloadTest < ActiveSupport::TestCase
  def build_report(report_data)
    Report.new(
      report_name: "WB",
      organization_id: organizations(:acme).id,
      user: users(:admin_user),
      report_type: "whitebox",
      generated_at: Time.current,
      report_data: report_data
    )
  end

  test "filters out non-vulnerable findings" do
    rows = [
      { "target" => "1.1.1.1", "port" => 22, "isVulnerable" => true,  "exploit" => "ssh" },
      { "target" => "2.2.2.2", "port" => 80, "isVulnerable" => false, "exploit" => "http" }
    ]
    payload = Aegis::Reports::WhiteboxPayload.new(build_report(rows)).to_h

    assert_equal "WB", payload[:report_name]
    assert_equal "whitebox", payload[:scan_type]
    assert_equal 1, payload[:findings].length
    assert_equal "1.1.1.1", payload[:findings].first[:target]
  end

  test "accepts symbol keys in report_data rows" do
    rows = [
      { target: "1.1.1.1", port: 443, isVulnerable: true, exploit: "ssl",
        exploit_name: "ssl_bug", severity: "high", cve_id: "CVE-2026-1",
        evidence: "boom", exploit_code: "rce" }
    ]
    payload = Aegis::Reports::WhiteboxPayload.new(build_report(rows)).to_h
    finding = payload[:findings].first

    assert_equal "1.1.1.1", finding[:target]
    assert_equal 443, finding[:port]
    assert_equal true, finding[:isVulnerable]
    assert_equal "ssl_bug", finding[:exploit_name]
    assert_equal "high", finding[:severity]
    assert_equal "CVE-2026-1", finding[:cve_id]
    assert_equal "boom", finding[:evidence]
    assert_equal "rce", finding[:exploit_code]
  end

  test "to_json produces valid JSON of to_h" do
    rows = [{ "target" => "1.1.1.1", "port" => 22, "isVulnerable" => true }]
    payload = Aegis::Reports::WhiteboxPayload.new(build_report(rows))
    parsed = JSON.parse(payload.to_json)

    assert_equal "WB", parsed["report_name"]
    assert_equal 1, parsed["findings"].length
  end

  test "handles nil report_data gracefully" do
    payload = Aegis::Reports::WhiteboxPayload.new(build_report(nil)).to_h
    assert_equal [], payload[:findings]
  end
end
