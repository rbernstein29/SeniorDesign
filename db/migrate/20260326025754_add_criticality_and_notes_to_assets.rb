class AddCriticalityAndNotesToAssets < ActiveRecord::Migration[8.0]
  def change
    add_column :assets, :criticality, :string, default: 'unknown'
    add_column :assets, :notes, :text
  end
end
