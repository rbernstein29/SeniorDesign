class Asset < ApplicationRecord
  belongs_to :organization, class_name: "Organization", foreign_key: :organization_id

  self.table_name = "vuln_scanner.assets"
  validates :ip_address, presence: true
end
