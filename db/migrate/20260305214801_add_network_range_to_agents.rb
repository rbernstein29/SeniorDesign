class AddNetworkRangeToAgents < ActiveRecord::Migration[8.0]
  def change
    add_column :agents, :network_range, :string
  end
end
