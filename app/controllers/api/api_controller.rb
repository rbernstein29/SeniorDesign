module Api
  class ApiController < ActionController::API
    before_action :authenticate_api_key!

    private

    def authenticate_api_key!
      user = User.find_by(api_key: params[:api_key])
      if user && ActiveSupport::SecurityUtils.secure_compare(user.api_key, params[:api_key])
        @current_user = user
      else
        render json: { error: "Invalid API key" }, status: :unauthorized
      end
    end

    def require_api_admin!
      unless @current_user.access_level == "admin"
        render json: { error: "Admin access required" }, status: :forbidden
      end
    end
  end
end
