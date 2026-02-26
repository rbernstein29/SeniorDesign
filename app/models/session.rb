class Session < ApplicationRecord
  belongs_to :user

  EXPIRY = 1.hours

  def expired?
    last_active_at.present? && last_active_at < EXPIRY.ago
  end
end
