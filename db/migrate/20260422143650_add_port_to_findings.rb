class AddPortToFindings < ActiveRecord::Migration[8.0]
  def change
    add_column :findings, :port, :integer
  end
end
