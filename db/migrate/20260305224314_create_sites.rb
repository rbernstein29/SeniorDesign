class CreateSites < ActiveRecord::Migration[8.0]
  def change
    create_table :sites do |t|
      t.integer :organization_id, null: false
      t.string :name, null: false
      t.string :network_range

      t.timestamps
    end
  end
end
