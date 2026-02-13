module Api
  class UsersController < ApplicationController
    skip_before_action :verify_authenticity_token
    allow_unauthenticated_access only: [:signin, :create] 
   
    # GET /api/users
    def index
      users = User.all
      render json: users
    end

    # GET /api/users/:id
    def show
      user = User.find(params[:id])
      render json: user
    end

    # POST /api/users
    def create
      user = User.new(user_params)
      if user.save
        render json: { success: true, url: "/assets" }, status: :created
      else
        render json: { success: false, errors: user.errors.full_messages }, status: :unprocessable_entity
      end
    end

    # POST /api/users/signin
    def signin
      user = User.find_by(email_address: params[:user][:email_address])

      if user&.authenticate(params[:user][:password])
        start_new_session_for user
        render json: { success: true, url: "/assets" }
      else
        render json: { success: false }, status: :unauthorized
      end
    end

    # POST /api/users/signout
    def signout
      terminate_session
      render json: { success: true }
    end

    private

    def user_params
      params.require(:user).permit(:name, :email_address, :password, :password_confirmation, :org_id, :access_level)
    end

  end
end
