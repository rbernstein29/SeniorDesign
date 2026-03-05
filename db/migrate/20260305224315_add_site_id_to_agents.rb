class AddSiteIdToAgents < ActiveRecord::Migration[8.0]
  def change
    add_column :agents, :site_id, :integer
  end
end
