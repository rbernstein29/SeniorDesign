require "prawn"
require "prawn/table"

class ScanReportPdf < Prawn::Document
  def initialize(report)
    super()
    @report = report

    font "Helvetica"

    header
    move_down 20
    scan_info
    move_down 20
    chart
    move_down 20
    findings_table

    number_pages "Page <page> of <total>", at: [bounds.right - 150, 0],
      width: 150, align: :right, size: 10
  end

  def header
    text "Vulnerability Scan Report", size: 24, style: :bold
    stroke_horizontal_rule
  end

  def scan_info
    move_down 10
    text "Report ID: ##{@report.id}", size: 14, style: :bold
    text "Generated At: #{@report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}"
    text "Organization ID: #{@report.organization_id}"
    text "Initiated By: #{@report.user&.email_address || 'Unknown'}"
  end

  def chart
    text "Vulnerability Summary", size: 18, style: :bold
    move_down 15

    raw = @report.report_data || []
    raw = JSON.parse(raw) if raw.is_a?(String)
    results = raw.map(&:with_indifferent_access)
    total = results.count
    return if total.zero?

    vulnerable_count = results.count { |r| r[:success] }
    secure_count = total - vulnerable_count

    max_width = 300
    bar_height = 20
    label_width = 80
    spacing = 10

    vuln_width = (vulnerable_count.to_f / total * max_width)
    text_box "Vulnerable", at: [0, cursor], width: label_width, height: bar_height, valign: :center, style: :bold

    if vuln_width > 0
      fill_color "EF4444"
      fill_rectangle [label_width, cursor], vuln_width, bar_height
      fill_color "000000"
    end
    text_box "#{vulnerable_count} (#{(vulnerable_count.to_f / total * 100).round}%)", at: [label_width + vuln_width + 10, cursor], width: 100, height: bar_height, valign: :center
    move_down bar_height + spacing

    secure_width = (secure_count.to_f / total * max_width)
    text_box "Secure", at: [0, cursor], width: label_width, height: bar_height, valign: :center, style: :bold
    if secure_width > 0
      fill_color "10B981"
      fill_rectangle [label_width, cursor], secure_width, bar_height
      fill_color "000000"
    end
    text_box "#{secure_count} (#{(secure_count.to_f / total * 100).round}%)", at: [label_width + secure_width + 10, cursor], width: 100, height: bar_height, valign: :center
  end

  def findings_table
    text "Scan Results", size: 18, style: :bold
    move_down 10

    raw = @report.report_data || []
    raw = JSON.parse(raw) if raw.is_a?(String)
    results = raw
    if results.empty?
      text "No results found.", style: :italic
      return
    end

    data = [["Target", "Port", "Exploit Name", "CVE", "Severity", "Status", "Time"]]

    results.each do |result|
      r = result.with_indifferent_access
      status = r[:success] ? "VULNERABLE" : "Secure"

      data << [
        r[:target],
        r[:port].to_s,
        r[:exploit_name].presence || r[:exploit],
        r[:cve_id].presence || "—",
        r[:severity]&.upcase || "—",
        status,
        (Time.parse(r[:timestamp].to_s).strftime("%H:%M:%S") rescue r[:timestamp].to_s)
      ]
    end

    table(data, header: true, width: bounds.width) do
      row(0).font_style = :bold
      row(0).background_color = "F0F0F0"
      cells.padding = 8
      cells.borders = [:bottom]
      cells.border_width = 0.5

      column(5).each do |cell|
        if cell.content == "VULNERABLE"
          cell.text_color = "CC0000"
          cell.font_style = :bold
        elsif cell.content == "Secure"
          cell.text_color = "006600"
        end
      end
    end
  end
end
