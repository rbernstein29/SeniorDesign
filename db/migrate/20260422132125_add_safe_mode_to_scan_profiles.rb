class AddSafeModeToScanProfiles < ActiveRecord::Migration[8.0]
  def change
    add_column :scan_profiles, :safe_mode, :boolean, default: false, null: false
  end
end
