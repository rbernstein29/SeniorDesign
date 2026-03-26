class ScanProfile < ApplicationRecord
  belongs_to :organization
  validates :name, presence: true

  def exploits = Exploit.where(id: exploit_ids)
end
