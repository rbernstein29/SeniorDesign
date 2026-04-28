class FindingsController < ApplicationController
  def ai_remediation
    finding = Finding.joins(:asset)
                     .where(assets: { organization_id: current_org_id })
                     .includes(:exploit)
                     .find(params[:id])

    if finding.ai_remediation.blank? && !finding.ai_remediation_pending?
      finding.update_column(:ai_remediation_pending, true)
      log_activity(
        text: "AI remediation requested for <strong>#{ERB::Util.h(finding.exploit&.name || "finding ##{finding.id}")}</strong>",
        color: 'violet'
      )
      text = OllamaService.remediation_for(finding.exploit, finding)
      finding.update_columns(ai_remediation: text, ai_remediation_pending: false)
    end

    render json: { text: finding.ai_remediation, pending: finding.ai_remediation_pending? }
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'Finding not found.' }, status: :not_found
  end

  def ai_remediation_status
    finding = Finding.joins(:asset)
                     .where(assets: { organization_id: current_org_id })
                     .find(params[:id])

    render json: {
      pending: finding.ai_remediation_pending?,
      done:    finding.ai_remediation.present?,
      text:    finding.ai_remediation
    }
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'Not found.' }, status: :not_found
  end
end
