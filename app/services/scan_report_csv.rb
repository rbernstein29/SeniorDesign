require "csv"

class ScanReportCsv
  def initialize(report)
    @report = report
  end

  def render
    serializer = Aegis::ReportRowSerializer.new(@report)
    CSV.generate do |csv|
      csv << serializer.headers
      serializer.rows.each { |row| csv << row }
    end
  end
end
