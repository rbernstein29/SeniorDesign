class Site < ApplicationRecord
  validates :name, presence: true
  has_many :agents, foreign_key: :site_id
  has_many :assets, foreign_key: :site_id
end
