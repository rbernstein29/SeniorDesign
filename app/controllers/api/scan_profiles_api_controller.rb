module Api
  class ScanProfilesApiController < ApiController
    before_action :require_api_admin!

    def index
      profiles = ScanProfile.where(organization_id: @current_user.organization_id).order(:name)
      render json: { scan_profiles: profiles.map { |p| profile_json(p) } }
    end

    # Body: name, description, safe_mode (true/false), exploit_ids (array of ints)
    def create
      profile = ScanProfile.new(
        organization_id: @current_user.organization_id,
        name:            params[:name].to_s.strip,
        description:     params[:description].presence,
        safe_mode:       params[:safe_mode].to_s == "true",
        exploit_ids:     Array(params[:exploit_ids]).map(&:to_i).select { |id| id > 0 }
      )
      if profile.save
        render json: { scan_profile: profile_json(profile) }, status: :created
      else
        render json: { error: profile.errors.full_messages.join(", ") }, status: :unprocessable_entity
      end
    end

    def destroy
      profile = ScanProfile.where(organization_id: @current_user.organization_id).find(params[:id])
      profile.destroy
      render json: { deleted: true, id: params[:id].to_i }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Scan profile not found" }, status: :not_found
    end

    private

    def profile_json(p)
      {
        id:          p.id,
        name:        p.name,
        description: p.description,
        safe_mode:   p.safe_mode,
        exploit_ids: p.exploit_ids,
        created_at:  p.created_at
      }
    end
  end
end
