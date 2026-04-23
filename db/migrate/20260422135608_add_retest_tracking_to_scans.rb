class AddRetestTrackingToScans < ActiveRecord::Migration[8.0]
  def change
    add_column :scans, :is_retest, :boolean, default: false, null: false
    add_column :scans, :retest_of, :integer
  end
end
