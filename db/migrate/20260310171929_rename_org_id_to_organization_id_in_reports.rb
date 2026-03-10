class RenameOrgIdToOrganizationIdInReports < ActiveRecord::Migration[8.0]
  def change
    rename_column :"vuln_scanner.reports", :org_id, :organization_id
  end
end
