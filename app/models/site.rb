class Site < ApplicationRecord
  self.table_name = "vuln_scanner.sites"
  validates :name, presence: true
  has_many :agents, foreign_key: :site_id
  has_many :assets, foreign_key: :site_id
end
