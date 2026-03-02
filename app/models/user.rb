class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy
  has_many :reports

  normalizes :email_address, with: ->(e) { e.strip.downcase }

  self.table_name = "vuln_scanner.users"
end
