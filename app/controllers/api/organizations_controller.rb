module Api
  class OrganizationsController < ApplicationController
   
    # GET /api/organizations
    def index
      organizations = Organization.all
      render json: organizations
    end

    # GET /api/organizations/:id
    def show
      organization = Organization.find(params[:id])
      render json: organization
    end

    # POST /api/organizations
    def create
      organization = Organization.new(organization_params)
      if organization.save
        render json: organization, status: :created
      else
        render json: { errors: organization.errors.full_messages }, status: :unprocessable_entity
      end
    end

    private

    def organization_params
      params.require(:organization).permit(:org_name, :org_domain)
    end

  end
end
