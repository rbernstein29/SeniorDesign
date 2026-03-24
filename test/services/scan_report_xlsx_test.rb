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
end
