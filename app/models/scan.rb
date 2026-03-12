class Scan < ApplicationRecord
  # scans table is in the public schema (not vuln_scanner)
  # FK column is org_id, not organization_id
  belongs_to :organization, foreign_key: :org_id
  belongs_to :user, foreign_key: :initiated_by, optional: true
  has_many :reports

  scope :for_org,   ->(org_id) { where(org_id: org_id) }
  scope :running,   -> { where(status: 'running') }
  scope :completed, -> { where(status: 'completed') }
  scope :failed,    -> { where(status: %w[failed cancelled]) }
end
