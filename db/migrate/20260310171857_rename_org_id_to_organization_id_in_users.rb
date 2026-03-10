class RenameOrgIdToOrganizationIdInUsers < ActiveRecord::Migration[8.0]
  def change
    rename_column :"vuln_scanner.users", :org_id, :organization_id
  end
end
