class RenameOrgIdToOrganizationIdInAssets < ActiveRecord::Migration[8.0]
  def change
    rename_column :"vuln_scanner.assets", :org_id, :organization_id
  end
end
