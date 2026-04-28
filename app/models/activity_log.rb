class ActivityLog < ApplicationRecord
  belongs_to :organization, optional: true
  belongs_to :user, optional: true

  LIMIT_PER_ORG = 10

  scope :for_org, ->(org_id) { where(organization_id: org_id) }

  after_create :prune_old_entries

  private

  def prune_old_entries
    keep_ids = ActivityLog.where(organization_id: organization_id)
                          .order(created_at: :desc)
                          .limit(LIMIT_PER_ORG)
                          .select(:id)
    ActivityLog.where(organization_id: organization_id)
               .where.not(id: keep_ids)
               .delete_all
  rescue => e
    Rails.logger.warn "ActivityLog prune failed: #{e.message}"
  end
end
