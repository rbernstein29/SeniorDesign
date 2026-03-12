class ReportsController < ApplicationController

  def destroy
    report = Report.find(params[:id])
    report.destroy
    redirect_to reports_path, notice: 'Report deleted.'
  rescue ActiveRecord::RecordNotFound
    redirect_to reports_path, alert: 'Report not found'
  end
  
end
