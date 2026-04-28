class AddAiRemediationPendingToFindings < ActiveRecord::Migration[8.0]
  def change
    add_column :findings, :ai_remediation_pending, :boolean, default: false, null: false
  end
end
