require "prawn"
require "prawn/table"

class ScanReportPdf < Prawn::Document
  def initialize(report)
    super()
    @report = report
    @safe   = report.report_type == 'reconnaissance'

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
    title = @safe ? "Reconnaissance / Safe Mode Scan Report" : "Vulnerability Scan Report"
    text title, size: 24, style: :bold
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
    text(@safe ? "Reconnaissance Summary" : "Vulnerability Summary", size: 18, style: :bold)
    move_down 15

    raw = @report.report_data || []
    raw = JSON.parse(raw) if raw.is_a?(String)
    results = raw.map(&:with_indifferent_access)
    total = results.count
    return if total.zero?

    detected_count   = results.count { |r| r[:success] }
    undetected_count = total - detected_count

    max_width  = 300
    bar_height = 20
    label_width = 100
    spacing    = 10

    detected_label   = @safe ? "Detected"     : "Vulnerable"
    undetected_label = @safe ? "Not Detected" : "Secure"
    detected_color   = @safe ? "CC7700"       : "EF4444"

    det_width = (detected_count.to_f / total * max_width)
    text_box detected_label, at: [0, cursor], width: label_width, height: bar_height, valign: :center, style: :bold

    if det_width > 0
      fill_color detected_color
      fill_rectangle [label_width, cursor], det_width, bar_height
      fill_color "000000"
    end
    text_box "#{detected_count} (#{(detected_count.to_f / total * 100).round}%)", at: [label_width + det_width + 10, cursor], width: 100, height: bar_height, valign: :center
    move_down bar_height + spacing

    undet_width = (undetected_count.to_f / total * max_width)
    text_box undetected_label, at: [0, cursor], width: label_width, height: bar_height, valign: :center, style: :bold
    if undet_width > 0
      fill_color "10B981"
      fill_rectangle [label_width, cursor], undet_width, bar_height
      fill_color "000000"
    end
    text_box "#{undetected_count} (#{(undetected_count.to_f / total * 100).round}%)", at: [label_width + undet_width + 10, cursor], width: 100, height: bar_height, valign: :center
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

    if @safe
      data = [["Target", "Port", "Module", "Detected", "Evidence", "Time"]]
      results.each do |result|
        r = result.with_indifferent_access
        data << [
          r[:target],
          r[:port].to_s,
          r[:exploit_name].presence || r[:exploit],
          r[:success] ? "Yes" : "No",
          r[:evidence].to_s.first(60),
          (Time.parse(r[:timestamp].to_s).strftime("%H:%M:%S") rescue r[:timestamp].to_s)
        ]
      end

      table(data, header: true, width: bounds.width) do
        row(0).font_style = :bold
        row(0).background_color = "F0F0F0"
        cells.padding = 8
        cells.borders = [:bottom]
        cells.border_width = 0.5

        column(3).each do |cell|
          next if cell.row == 0
          cell.text_color = cell.content == "Yes" ? "CC7700" : "006600"
          cell.font_style = :bold if cell.content == "Yes"
        end
      end
    else
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
end
