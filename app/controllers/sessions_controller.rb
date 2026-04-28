class SessionsController < ApplicationController
  allow_unauthenticated_access only: %i[ new create ]
  rate_limit to: 10, within: 3.minutes, only: :create, with: -> { redirect_to new_session_url, alert: "Try again later." }

  def new
  end

  def create
    if user = User.authenticate_by(params.permit(:email_address, :password))
      if user.email_verified_at.nil?
        redirect_to verify_pending_path
      else
        start_new_session_for user
        log_activity(text: "User <strong>#{ERB::Util.h(user.name)}</strong> signed in", color: 'blue', org_id: user.organization_id, uid: user.id)
        redirect_to after_authentication_url
      end
    else
      redirect_to login_path, alert: "Try another email address or password."
    end
  end

  def destroy
    user = Current.user
    org_id = user&.organization_id
    log_activity(text: "User <strong>#{ERB::Util.h(user.name)}</strong> signed out", color: 'blue', org_id: org_id, uid: user&.id) if user
    terminate_session
    redirect_to login_path
  end
end
