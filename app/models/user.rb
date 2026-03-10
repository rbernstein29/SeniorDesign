class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy
  has_many :reports

  normalizes :email_address, with: ->(e) { e.strip.downcase }
  validates :email_address, uniqueness: { scope: :org_id, case_sensitive: false, message: "is already registered in this organization" }

  self.table_name = "vuln_scanner.users"
end
