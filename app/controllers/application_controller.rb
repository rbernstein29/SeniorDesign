class ApplicationController < ActionController::Base
  include Authentication
  # Only allow modern browsers supporting webp images, web push, badges, import maps, CSS nesting, and CSS :has.
  before_action :set_no_cache
  allow_browser versions: :modern

  helper_method :admin?

  private

  def current_org_id
    Current.user&.organization_id
  end
  helper_method :current_org_id

  def admin?
    Current.user&.access_level == "admin"
  end

  def require_admin
    unless Current.user&.access_level == "admin"
      redirect_to root_path, alert: "You don't have permission to access this page."
    end
  end

  def set_no_cache
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
  end

end
