require "test_helper"

class ScanReportXlsxTest < ActiveSupport::TestCase
  def report_with_data
    reports(:report_one)
  end

  def report_without_data
    reports(:report_two)
  end

  test "renders without error for report with data" do
    result = ScanReportXlsx.new(report_with_data).render
    assert result.is_a?(String)
    assert result.length > 0
  end

  test "renders without error for report with nil report_data" do
    result = ScanReportXlsx.new(report_without_data).render
    assert result.is_a?(String)
    assert result.length > 0
  end

  test "output is a valid zip (xlsx) file" do
    result = ScanReportXlsx.new(report_with_data).render
    # xlsx files are ZIP archives starting with PK signature
    assert_equal "PK", result.force_encoding("BINARY")[0, 2]
  end

  test "renders a reconnaissance (safe-mode) report with the safe summary block" do
    recon = Report.create!(
      report_name: "Recon",
      organization_id: organizations(:acme).id,
      user_id:        users(:admin_user).id,
      report_type:    "reconnaissance",
      generated_at:   Time.current,
      report_data: [
        { "target" => "1.1.1.1", "port" => 80, "exploit" => "http",
          "success" => true, "evidence" => "200 OK", "timestamp" => "2026-04-01T10:00:00Z" },
        { "target" => "1.1.1.2", "port" => 22, "exploit" => "ssh",
          "success" => false, "evidence" => "no", "timestamp" => "2026-04-01T10:00:01Z" }
      ]
    )
    result = ScanReportXlsx.new(recon).render
    assert result.length > 0
    assert_equal "PK", result.force_encoding("BINARY")[0, 2]
  end
end
