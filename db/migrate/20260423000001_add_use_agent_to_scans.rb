class AddUseAgentToScans < ActiveRecord::Migration[7.2]
  def change
    add_column :scans, :use_agent, :boolean, default: false, null: false
  end
end
