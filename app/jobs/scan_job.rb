class ScanJob < ApplicationJob
  queue_as :default

  def perform(org_id, exploit_ids, user_id, asset_ids = [], scan_options = {})
    user = User.find_by(id: user_id)
    return unless user

    broadcast_progress(user_id, 0, "Initializing scan...")

    asset_ids = Array(asset_ids).map(&:to_i).select { |id| id > 0 }
    total = asset_ids.any? ? asset_ids.size : Asset.where(organization_id: org_id, is_active: true).count
    scan = Scan.create!(
      scan_name:       "Scan #{Time.current.strftime('%Y-%m-%d %H:%M')}",
      organization_id: org_id,
      initiated_by: user_id,
      status:       'running',
      start_time:   Time.current,
      total_assets: total
    )

    agents = Agent.where(organization_id: org_id).select(&:connected?)
    if agents.empty?
      scan.update!(status: 'failed', end_time: Time.current)
      broadcast_progress(user_id, 0, "Error: No connected agents found.", error: true)
      return
    end

    broadcast_progress(user_id, 10, "Starting scan via #{agents.count} agent(s)...")

    ScanService.new(org_id, exploit_ids, user_id, scan, asset_ids, scan_options).perform

    broadcast_complete(user_id)
  rescue => e
    scan&.update!(status: 'failed', end_time: Time.current)
    broadcast_progress(user_id, 0, "Scan failed: #{e.message}", error: true)
    raise
  end

  private

  def broadcast_progress(user_id, percent, status, error: false)
    color = error ? "var(--red)" : "var(--blue)"
    html = <<~HTML
      <div class="progress-container">
          <div class="progress-bar-bg">
              <div class="progress-bar-fill" style="width: #{percent}%; background: #{color};"></div>
          </div>
          <div class="progress-label">
              <span class="progress-text">#{status}</span>
              <span class="progress-percent" style="color: #{color};">#{percent}%</span>
          </div>
      </div>
    HTML

    Turbo::StreamsChannel.broadcast_update_to(
      "scan_progress_#{user_id}",
      target: "scan_progress_area",
      html: html
    )
  end

  def broadcast_complete(user_id)
    html = <<~HTML
      <div class="progress-container">
          <div class="progress-bar-bg">
              <div class="progress-bar-fill" style="width: 100%; background: var(--green);"></div>
          </div>
          <div class="progress-label">
              <span class="progress-text" style="color: var(--green);">Scan Complete</span>
              <a href="/reports" class="progress-percent" style="text-decoration: underline; color: var(--green);">View Report -></a>
          </div>
      </div>
    HTML

    Turbo::StreamsChannel.broadcast_update_to(
      "scan_progress_#{user_id}",
      target: "scan_progress_area",
      html: html
    )
  end
end
