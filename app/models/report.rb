class Report < ApplicationRecord
  self.table_name = "vuln_scanner.reports"

  belongs_to :user
  belongs_to :scan, optional: true
end
