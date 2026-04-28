module Api
  class AuthApiController < ActionController::API
    # POST /api/auth
    # Body: email_address, password
    # Returns the user's API key on success — all subsequent requests use the key.
    def create
      email    = params[:email_address].to_s.strip.downcase
      password = params[:password].to_s

      if email.blank? || password.blank?
        render json: { error: "email_address and password are required" }, status: :bad_request
        return
      end

      user = User.authenticate_by(email_address: email, password: password)

      if user.nil?
        render json: { error: "Invalid email or password" }, status: :unauthorized
        return
      end

      unless user.email_verified_at.present?
        render json: { error: "Email address not verified" }, status: :forbidden
        return
      end

      if user.api_key.blank?
        user.update!(api_key: SecureRandom.urlsafe_base64(32))
      end

      render json: {
        api_key:      user.api_key,
        name:         user.name,
        email:        user.email_address,
        access_level: user.access_level
      }
    end
  end
end
