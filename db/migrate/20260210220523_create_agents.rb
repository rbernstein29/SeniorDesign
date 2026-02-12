class CreateAgents < ActiveRecord::Migration[7.0]
  def change
    create_table :agents do |t|
      t.string :agent_id, null: false, index: { unique: true }
      t.integer :organization_id, default: 1  # Simplified - no foreign key for now
      
      t.text :ssh_public_key
      t.text :ssh_private_key
      t.string :ssh_key_fingerprint
      t.integer :tunnel_port, null: false
      
      t.string :platform
      t.string :hostname
      t.string :status, default: 'created'
      t.datetime :last_seen
      
      t.timestamps
    end
  end
end