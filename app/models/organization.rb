class Organization < ApplicationRecord
  self.table_name = "vuln_scanner.organizations"
  validates :org_name, presence: true, uniqueness: { case_sensitive: false, message: "is already registered" }
end
