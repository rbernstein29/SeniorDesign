class AccountsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]
  allow_unauthenticated_access only: [:create]
  
  def create
    ActiveRecord::Base.transaction do 
      @organization = Organization.create!(organization_params)
      @user = User.create!(user_params.merge(org_id: @organization.id, access_level: "admin"))

      start_new_session_for @user
      redirect_to root_path
    end
  rescue ActiveRecord::RecordInvalid => e
    redirect_to login_path, alert: e.message
  end

  private

  def user_params
    params.require(:user).permit(:name, :email_address, :password, :password_confirmation, :org_id, :access_level)
  end

  def organization_params
    params.require(:organization).permit(:org_name)
  end

end
