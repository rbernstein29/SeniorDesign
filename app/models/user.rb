class User < ApplicationRecord
  has_secure_password
  has_many :sessions, dependent: :destroy
  belongs_to :organization

  normalizes :email_address, with: ->(e) { e.strip.downcase }
  validates :email_address, uniqueness: { scope: :organization_id, case_sensitive: false, message: "is already registered in this organization" }

  generates_token_for :email_verification, expires_in: 30.minutes do
    email_verified_at
  end

end
