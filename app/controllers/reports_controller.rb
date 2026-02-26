module Api
  class ReportsController < ApplicationController
 
    # GET /api/reports
    def index
      reports = Report.all
      render json: reports
    end

    # GET /api/reports/:id
    def show
      report = User.find(params[:id])
      render json: report
    end

    # POST /api/reports
    def create
      report = Report.new(report_params)
      if report.save
        render json: { success: true }, status: :created
      else
        render json: { success: false, errors: report.errors.full_messages }, status: :unprocessable_entity
      end
    end

    private

    def report_params
      params.require(:report).permit(:report_name, :scan_id, :org_id, :generated_by, :report_type, :report_format, :report_data, :file_path)
    end

  end
end
