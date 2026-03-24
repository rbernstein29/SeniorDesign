class Scan < ApplicationRecord
  belongs_to :organization
  belongs_to :user, foreign_key: :initiated_by, optional: true
  has_many :reports

  scope :for_org,   ->(org_id) { where(organization_id: org_id) }
  scope :running,   -> { where(status: 'running') }
  scope :completed, -> { where(status: 'completed') }
  scope :failed,    -> { where(status: %w[failed cancelled]) }
end
