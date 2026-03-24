class DropGlobalEmailUniquenessFromUsers < ActiveRecord::Migration[8.0]
  def change
    remove_index :users, name: "users_email_key"
  end
end
