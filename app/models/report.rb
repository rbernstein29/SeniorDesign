class Report < ApplicationRecord
  belongs_to :user
  belongs_to :scan, optional: true
end
