class OperatingSystem < ApplicationRecord
  has_many :exploit_os_compatibilities, dependent: :destroy
  has_many :exploits, through: :exploit_os_compatibilities
  has_many :assets, foreign_key: :os_id, dependent: :nullify
end
