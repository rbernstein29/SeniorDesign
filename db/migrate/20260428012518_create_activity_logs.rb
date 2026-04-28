class CreateActivityLogs < ActiveRecord::Migration[8.0]
  def change
    create_table :activity_logs do |t|
      t.integer :organization_id, null: false
      t.integer :user_id
      t.string  :color, null: false, default: 'blue'
      t.text    :text,  null: false
      t.timestamps
    end
    add_index :activity_logs, [:organization_id, :created_at]
  end
end
