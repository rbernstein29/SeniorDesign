class ScanJob < ApplicationJob
  queue_as :default

  def perform(org_id, exploit_ids, user_id)
    user = User.find_by(id: user_id)
    return unless user

    broadcast_progress(user_id, 0, "Initializing scan...")

    # Create a Scan record immediately so the Scans page reflects the running scan
    scan = Scan.create!(
      scan_name: "Scan #{Time.current.strftime('%Y-%m-%d %H:%M')}",
      org_id: org_id,
      initiated_by: user_id,
      status: 'running',
      start_time: Time.current,
      total_assets: Asset.where(organization_id: org_id, is_active: true).count
    )

    # Find all connected agents for this organization
    agents = Agent.where(organization_id: org_id).select(&:connected?)

    if agents.empty?
      broadcast_progress(user_id, 0, "Error: No connected agents found.", error: true)
      scan.update!(status: 'failed', end_time: Time.current)
      Report.create!(
        report_name: "scan-#{scan.id}-error",
        scan_id: scan.id,
        organization_id: org_id,
        generated_by: user_id,
        user_id: user_id,
        report_type: 'vulnerability',
        report_format: 'json',
        report_data: { error: "No connected agents found." },
        generated_at: Time.current
      )
      return
    end

    # Count total unique targets for the scan record
    all_targets = agents.flat_map(&:scan_targets).uniq
    scan.update!(total_assets: all_targets.count)

    # Calculate total operations for progress tracking
    total_ops = [all_targets.count * exploit_ids.count, 1].max
    current_op = 0
    cancelled = false

    scan_results = []

    agents.each do |agent|
      break if cancelled
      tunnel_port = agent.tunnel_port
      targets = agent.scan_targets

      targets.each do |target_ip|
        break if cancelled

        # Update progress for connection phase
        percent = (current_op.to_f / total_ops * 100).to_i
        broadcast_progress(user_id, percent, "Connecting to #{target_ip}...")

        # Connect via the agent's tunnel (SOCKS proxy)
        if ScanDriver.connect_network(target_ip, tunnel_port) == 1

          exploit_ids.each do |exploit_id|
            if Rails.cache.read("scan_cancelled_#{user_id}")
              cancelled = true
              break
            end

            # Update progress for attack phase
            percent = (current_op.to_f / total_ops * 100).to_i
            broadcast_progress(user_id, percent, "Attacking #{target_ip} (Exploit #{exploit_id})...")

            exploit = ScanDriver.get_exploit(exploit_id)
            next unless exploit

            success = ScanDriver.attack(exploit) == 1

            scan_results << {
              target: target_ip,
              agent: agent.agent_id,
              exploit_id: exploit_id,
              success: success,
              timestamp: Time.current
            }
            current_op += 1
          end

          ScanDriver.disconnect_network
          scan.increment!(:scanned_assets)
        else
          scan_results << { target: target_ip, error: "Failed to connect via agent #{agent.agent_id}" }
          current_op += exploit_ids.count
        end
      end
    end

    final_status = cancelled ? 'cancelled' : 'completed'
    scan.update!(
      status: final_status,
      end_time: Time.current,
      total_exploits_tested: scan_results.count { |r| r[:exploit_id] },
      findings_count: scan_results.count { |r| r[:success] }
    )

    if cancelled
      broadcast_progress(user_id, 100, "Scan Cancelled", error: true)
    else
      broadcast_complete(user_id)
    end

    # Save the report — report_data is JSONB, pass Ruby Array directly
    Report.create!(
      report_name: "scan-#{scan.id}-#{Time.current.strftime('%Y%m%d-%H%M%S')}",
      scan_id: scan.id,
      organization_id: org_id,
      generated_by: user_id,
      user_id: user_id,
      report_type: 'vulnerability',
      report_format: 'json',
      report_data: scan_results,
      generated_at: Time.current
    )
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