module Api
  class ReportsApiController < ApiController
    def index
      reports = @current_user.reports
      render json: reports
    end

    def show
      report = @current_user.reports.find(params[:id])
      render json: report
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end
  end
end
