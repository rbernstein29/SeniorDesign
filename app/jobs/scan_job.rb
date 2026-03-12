class ScanJob < ApplicationJob
  queue_as :default

  def perform(org_id, exploit_range, user_id)
    scan = Scan.create!(
      scan_name: "Scan #{Time.current.strftime('%Y-%m-%d %H:%M')}",
      org_id: org_id,
      initiated_by: user_id,
      status: 'running',
      start_time: Time.current,
      total_assets: Asset.where(organization_id: org_id, is_active: true).count
    )

    ScanService.new(org_id, exploit_range, user_id, scan).perform
  rescue => e
    scan&.update!(status: 'failed', end_time: Time.current)
    raise
  end
end
