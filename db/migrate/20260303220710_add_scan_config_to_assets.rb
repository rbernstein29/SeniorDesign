class AddScanConfigToAssets < ActiveRecord::Migration[8.0]
  def change
    add_column :assets, :scan_config, :jsonb, default: {}
  end
end
