class Finding < ApplicationRecord
  self.table_name = 'vuln_scanner.findings'

  belongs_to :exploit, optional: true

  SEVERITY_ORDER = %w[critical high medium low].freeze

  scope :for_org, ->(org_id) {
    joins("JOIN public.assets ON public.assets.id = vuln_scanner.findings.asset_id")
      .where("public.assets.organization_id = ?", org_id)
  }

  def severity_badge_class
    case severity&.downcase
    when 'critical' then 'badge-critical'
    when 'high'     then 'badge-high'
    when 'medium'   then 'badge-medium'
    else                 'badge-low'
    end
  end
end
