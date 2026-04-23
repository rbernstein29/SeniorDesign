class Report < ApplicationRecord
  belongs_to :user
  belongs_to :scan, optional: true

  def whitebox?    = report_type == 'whitebox'
  def safe_mode?   = report_type == 'reconnaissance'
  def display_type
    case report_type
    when 'reconnaissance' then 'Safe Mode'
    when 'whitebox'       then 'Whitebox'
    else                       'Exploit'
    end
  end
end
