module ActivityLogger
  extend ActiveSupport::Concern

  def log_activity(text:, color: 'blue', org_id: nil, uid: nil)
    oid = org_id || Current.user&.organization_id || @current_user&.organization_id
    user_id = uid || Current.user&.id || @current_user&.id
    return unless oid
    ActivityLog.create!(organization_id: oid, user_id: user_id, color: color, text: text)
  rescue => e
    Rails.logger.warn "ActivityLog: #{e.message}"
  end
end
