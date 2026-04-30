require "test_helper"

class Aegis::ReportRowSerializerTest < ActiveSupport::TestCase
  S = Aegis::ReportRowSerializer

  def build_report(type, data)
    Report.new(
      report_name: "T",
      organization_id: organizations(:acme).id,
      user: users(:admin_user),
      report_type: type,
      generated_at: Time.current,
      report_data: data
    )
  end

  test "headers and rows for reconnaissance reports" do
    rows = [{ "target" => "1.1.1.1", "port" => 80, "exploit" => "http_enum",
              "success" => true, "evidence" => "200 OK",
              "timestamp" => "2026-04-01T12:30:45Z" }]
    s = S.new(build_report("reconnaissance", rows))
    assert s.safe?
    assert_equal Aegis::ReportRowSerializer::HEADERS_RECON, s.headers
    row = s.rows.first
    assert_equal "1.1.1.1", row[0]
    assert_equal "80", row[1]
    assert_equal "http_enum", row[2]
    assert_equal "Yes", row[3]
    assert_match(/12:30:45/, row[5])
  end

  test "recon row uses exploit_name when present" do
    rows = [{ "target" => "1.1.1.1", "port" => 22, "exploit" => "ssh", "exploit_name" => "SSH Probe",
              "success" => false, "evidence" => "n/a", "timestamp" => "bad" }]
    s = S.new(build_report("reconnaissance", rows))
    row = s.rows.first
    assert_equal "SSH Probe", row[2]
    assert_equal "No", row[3]
    assert_equal "bad", row[5]
  end

  test "vuln row resolves exploit cvss/cwe by exploit_id" do
    rows = [{ "target" => "1.1.1.1", "port" => 445,
              "exploit" => exploits(:exploit_one).exploit_id,
              "exploit_name" => exploits(:exploit_one).name,
              "cve_id" => "CVE-2017-0144", "severity" => "critical",
              "references" => [{ "type" => "URL", "value" => "https://example.com" }],
              "success" => true, "evidence" => "session opened",
              "timestamp" => "2026-04-01T12:00:00Z" }]
    s = S.new(build_report("full", rows))
    refute s.safe?
    row = s.rows.first
    assert_equal exploits(:exploit_one).cvss_score, row[5]
    assert_equal "VULNERABLE", row[11]
    assert_match(/URL: https/, row[10])
  end

  test "results parses JSON-stringified report_data" do
    raw = JSON.dump([{ "target" => "1.1.1.1" }])
    s = S.new(build_report("full", raw))
    assert_equal "1.1.1.1", s.results.first[:target]
  end

  test "exploit cache returns nil for blank id" do
    rows = [{ "target" => "1.1.1.1", "exploit" => nil }]
    s = S.new(build_report("full", rows))
    assert_nothing_raised { s.rows }
  end
end
