class CreateScanProfiles < ActiveRecord::Migration[8.0]
  def change
    create_table :scan_profiles do |t|
      t.integer :organization_id, null: false
      t.string  :name,            null: false
      t.text    :description
      t.integer :exploit_ids, array: true, default: []
      t.timestamps
    end
    add_index :scan_profiles, :organization_id
  end
end
