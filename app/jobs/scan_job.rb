class ScanJob < ApplicationJob
  queue_as :default

  def perform(org_id, exploit_range, user_id)
    ScanService.new(org_id, exploit_range, user_id).perform
  end
end
