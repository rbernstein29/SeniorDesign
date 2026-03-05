class Asset < ApplicationRecord
  self.table_name = "vuln_scanner.assets"
  validates :ip_address, presence: true
  belongs_to :site, optional: true
end
