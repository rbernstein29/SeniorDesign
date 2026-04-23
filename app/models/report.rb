class Report < ApplicationRecord
  belongs_to :user
  belongs_to :scan, optional: true

  def display_type = report_type == 'reconnaissance' ? 'Safe Mode' : 'Exploit'
  def safe_mode?   = report_type == 'reconnaissance'
end
