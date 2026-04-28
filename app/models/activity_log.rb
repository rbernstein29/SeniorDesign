class ActivityLog < ApplicationRecord
  belongs_to :organization, optional: true
  belongs_to :user, optional: true

  scope :for_org,  ->(org_id) { where(organization_id: org_id) }
  scope :last_day, -> { where('created_at > ?', 24.hours.ago) }
end
