class RenameEmailToEmailAddress < ActiveRecord::Migration[8.0]
  def change
    rename_column :users, :email, :email_address
  end
end
