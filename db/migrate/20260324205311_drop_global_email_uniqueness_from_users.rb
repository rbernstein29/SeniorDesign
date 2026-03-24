class DropGlobalEmailUniquenessFromUsers < ActiveRecord::Migration[8.0]
  def up
    execute "ALTER TABLE users DROP CONSTRAINT users_email_key"
  end

  def down
    execute "ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email_address)"
  end
end
