class AccountsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]
  allow_unauthenticated_access only: [:create, :verify_email, :verify_pending]

  def create
    ActiveRecord::Base.transaction do
      @organization = Organization.create!(organization_params)
      @user = User.create!(user_params.merge(organization_id: @organization.id, access_level: "admin"))
    end

    EmailVerifyMailer.verify(@user).deliver_now
    redirect_to verify_pending_path
  rescue ActiveRecord::RecordInvalid => e
    redirect_to login_path, alert: e.message
  rescue ActiveRecord::RecordNotUnique
    redirect_to login_path, alert: "That organization name or email is already registered."
  rescue => e
    Rails.logger.error "Verification email failed for user #{@user&.id}: #{e.message}"
    redirect_to verify_pending_path
  end

  def verify_pending
  end

  def verify_email
    user = User.find_by_token_for(:email_verification, params[:token])
    if user
      user.update!(email_verified_at: Time.current)
      start_new_session_for user
      redirect_to root_path, notice: "Email verified! Welcome to Aegis."
    else
      redirect_to login_path, alert: "Verification link is invalid or has expired."
    end
  end

  def generate_api_key
    Current.user.update(api_key: SecureRandom.urlsafe_base64(32))
    redirect_back_or_to root_path
  end

  private

  def user_params
    params.require(:user).permit(:name, :email_address, :password, :password_confirmation, :organization_id, :access_level)
  end

  def organization_params
    params.require(:organization).permit(:org_name)
  end

end
