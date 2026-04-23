class FindingsController < ApplicationController
  def ai_remediation
    finding = Finding.joins(:asset)
                     .where(assets: { organization_id: current_org_id })
                     .includes(:exploit)
                     .find(params[:id])

    if finding.ai_remediation.blank?
      text = GeminiService.remediation_for(finding.exploit, finding)
      finding.update_column(:ai_remediation, text)
    end

    render json: { text: finding.ai_remediation }
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'Finding not found.' }, status: :not_found
  end
end
