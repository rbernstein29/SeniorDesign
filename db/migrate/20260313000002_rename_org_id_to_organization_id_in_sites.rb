class RenameOrgIdToOrganizationIdInSites < ActiveRecord::Migration[7.2]
  def change
    rename_column :sites, :org_id, :organization_id if column_exists?(:sites, :org_id)
  end
end
