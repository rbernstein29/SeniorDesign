module Api
  class AccountApiController < ApiController

    def show
      org = @current_user.organization
      render json: {
        account: {
          id:           @current_user.id,
          name:         @current_user.name,
          email:        @current_user.email_address,
          access_level: @current_user.access_level,
          organization: {
            id:     org.id,
            name:   org.org_name,
            domain: org.org_domain
          }
        }
      }
    end
  end
end
