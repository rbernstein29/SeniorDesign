class AddAiRemediationToFindings < ActiveRecord::Migration[8.0]
  def change
    add_column :findings, :ai_remediation, :text
  end
end
