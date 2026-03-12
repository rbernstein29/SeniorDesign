class RenameOrgIdToOrganizationIdInScans < ActiveRecord::Migration[7.2]
  def change
    rename_column :scans, :org_id, :organization_id
  end
end
