module Api
  class ReportsApiController < ApiController
    before_action :require_api_admin!, only: [:retest]

    def index
      render json: { reports: org_reports.order(generated_at: :desc).map { |r| report_json(r) } }
    end

    def show
      report = org_reports.find(params[:id])
      render json: { report: report_json(report) }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def destroy
      report = org_reports.find(params[:id])
      log_activity(text: "[API] Report <strong>#{ERB::Util.h(report.report_name)}</strong> deleted",
                   color: 'red', org_id: @current_user.organization_id, uid: @current_user.id)
      report.destroy
      render json: { deleted: true, id: params[:id].to_i }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def download_json
      report = org_reports.find(params[:id])
      log_activity(text: "[API] Report <strong>#{ERB::Util.h(report.report_name)}</strong> downloaded (JSON)",
                   color: 'violet', org_id: @current_user.organization_id, uid: @current_user.id)
      send_data report.report_data.to_json,
        filename:    "#{report.report_name.parameterize}.json",
        type:        "application/json",
        disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def download_xlsx
      report = org_reports.find(params[:id])
      log_activity(text: "[API] Report <strong>#{ERB::Util.h(report.report_name)}</strong> downloaded (XLSX)",
                   color: 'violet', org_id: @current_user.organization_id, uid: @current_user.id)
      xlsx = ScanReportXlsx.new(report)
      send_data xlsx.render,
        filename:    "#{report.report_name.parameterize}.xlsx",
        type:        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def download_csv
      report = org_reports.find(params[:id])
      log_activity(text: "[API] Report <strong>#{ERB::Util.h(report.report_name)}</strong> downloaded (CSV)",
                   color: 'violet', org_id: @current_user.organization_id, uid: @current_user.id)
      csv = ScanReportCsv.new(report)
      send_data csv.render,
        filename:    "#{report.report_name.parameterize}.csv",
        type:        "text/csv",
        disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def download_whitebox_json
      report = org_reports.find(params[:id])
      log_activity(text: "[API] Report <strong>#{ERB::Util.h(report.report_name)}</strong> downloaded (Whitebox JSON)",
                   color: 'violet', org_id: @current_user.organization_id, uid: @current_user.id)
      unless report.whitebox?
        render json: { error: "Not a whitebox report" }, status: :unprocessable_entity
        return
      end

      send_data Aegis::Reports::WhiteboxPayload.new(report).to_json,
        filename:    "#{report.report_name.parameterize}-whitebox.json",
        type:        "application/json",
        disposition: "attachment"
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def data
      report = org_reports.find(params[:id])
      render json: { report_data: report.report_data }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    def retest
      report = org_reports.includes(:scan).find(params[:id])
      result = Aegis::Reports::Retester.new(
        report,
        organization_id: @current_user.organization_id,
        user_id:         @current_user.id
      ).call

      if result.queued?
        render json: {
          queued:       true,
          asset_count:  result.asset_count,
          module_count: result.module_count
        }, status: :accepted
      else
        render json: { error: result.error }, status: :unprocessable_entity
      end
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Report not found" }, status: :not_found
    end

    private

    def org_reports
      Report.where(user_id: User.where(organization_id: @current_user.organization_id).select(:id))
    end

    def report_json(r)
      {
        id:           r.id,
        report_name:  r.report_name,
        report_type:  r.report_type,
        report_format: r.report_format,
        scan_id:      r.scan_id,
        generated_at: r.generated_at,
        generated_by: r.generated_by
      }
    end
  end
end
