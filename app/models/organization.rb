class Organization < ApplicationRecord
  has_many :users, dependent: :destroy
  has_many :reports, dependent: :destroy
  has_many :assets, dependent: :destroy
  has_many :agents, dependent: :destroy
  has_many :scans, dependent: :destroy
  has_many :scan_profiles, dependent: :destroy

  validates :org_name, presence: true, uniqueness: { case_sensitive: false, message: "is already registered" }
end
