class AddOrgIdToAssets < ActiveRecord::Migration[8.0]
  def change
    add_column :assets, :organization_id, :integer
  end
end
