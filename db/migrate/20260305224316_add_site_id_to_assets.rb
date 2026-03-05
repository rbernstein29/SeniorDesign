class AddSiteIdToAssets < ActiveRecord::Migration[8.0]
  def change
    add_column :assets, :site_id, :integer
  end
end
