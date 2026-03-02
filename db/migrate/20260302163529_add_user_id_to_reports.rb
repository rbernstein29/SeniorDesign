class AddUserIdToReports < ActiveRecord::Migration[8.0]
  def change
    add_reference :reports, :user, null: false, foreign_key: true
  end
end
