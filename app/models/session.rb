class Session < ApplicationRecord
  belongs_to :user
  self.table_name = "vuln_scanner.sessions"

  EXPIRY = 1.hours

  def expired?
    last_active_at.present? && last_active_at < EXPIRY.ago
  end
end
