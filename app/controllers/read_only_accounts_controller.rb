class ReadOnlyAccountsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]
  
  def create
    ActiveRecord::Base.transaction do 
      @user = User.create!(user_params.merge(organization_id: Current.user&.organization_id, access_level: "read_only"))

      redirect_to read_only_accounts_path, alert: "Read-only user created."
    end
  rescue ActiveRecord::RecordInvalid => e
    redirect_to create_ro_account_path, alert: e.message
  rescue ActiveRecord::RecordNotUnique
    redirect_to create_ro_account_path, alert: "That email is already registered."
  end

  def index
    @read_only_users = User.where(
      organization_id: Current.user.organization_id,
      access_level: "read_only"
    )
  end

  def destroy
    user = User.find(params[:id])
    
    if user.organization_id == Current.user.organization_id && user.access_level == "read_only"
      user.destroy
      redirect_to read_only_accounts_path, alert: "User deleted."
    else
      redirect_to read_only_accounts_path, alert: "You don't have permission to delete this user."
    end
  rescue ActiveRecord::RecordNotFound
    redirect_to read_only_accounts_path, alert: "User not found."
  end

  def generate_api_key
    Current.user.update(api_key: SecureRandom.urlsafe_base64(32))
    redirect_back_or_to root_path
  end

  private

  def user_params
    params.require(:user).permit(:name, :email_address, :password, :password_confirmation, :organization_id, :access_level)
  end

end