class AddOrgIdToAssets < ActiveRecord::Migration[8.0]
  def change
    add_column :assets, :org_id, :integer
  end
end
