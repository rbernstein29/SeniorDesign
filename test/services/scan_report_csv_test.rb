require "test_helper"

class ScanReportCsvTest < ActiveSupport::TestCase
  def report_with_data
    reports(:report_one)
  end

  def report_without_data
    reports(:report_two)
  end

  test "renders without error for report with data" do
    result = ScanReportCsv.new(report_with_data).render
    assert result.is_a?(String)
    assert result.length > 0
  end

  test "renders without error for report with nil report_data" do
    result = ScanReportCsv.new(report_without_data).render
    assert result.is_a?(String)
  end

  test "output contains CSV header row" do
    result = ScanReportCsv.new(report_with_data).render
    assert_includes result, "Target"
    assert_includes result, "Port"
    assert_includes result, "Exploit"
    assert_includes result, "Status"
    assert_includes result, "Time"
  end

  test "output contains one row per finding" do
    result = ScanReportCsv.new(report_with_data).render
    rows = result.split("\n")
    # header + 2 data rows from fixture
    assert_equal 3, rows.length
  end

  test "VULNERABLE status appears for successful exploits" do
    result = ScanReportCsv.new(report_with_data).render
    assert_includes result, "VULNERABLE"
  end

  test "Secure status appears for unsuccessful exploits" do
    result = ScanReportCsv.new(report_with_data).render
    assert_includes result, "Secure"
  end
end
