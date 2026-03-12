class RenameOrgIdToOrganizationIdInScans < ActiveRecord::Migration[7.2]
  def change
    rename_column :scans, :org_id, :organization_id if column_exists?(:scans, :org_id)
  end
end
