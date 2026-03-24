module Api
  class ReportsApiController < ApiController
    def index
      reports = @current_user.organization.reports
      render json: reports
    end

    def show
      report = @current_user.organization.reports.find(params[:id])
      render json: report
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end
  end
end
