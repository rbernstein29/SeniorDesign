class Asset < ApplicationRecord
  belongs_to :organization, class_name: "Organization", foreign_key: :organization_id

  validates :ip_address, presence: true
  belongs_to :site, optional: true

  validate :ip_within_site_range, if: -> { site&.network_range.present? }

  private

  def ip_within_site_range
    cidr = IPAddr.new(site.network_range)
    unless cidr.include?(IPAddr.new(ip_address.to_s))
      errors.add(:ip_address, "is outside the site's network range (#{site.network_range})")
    end
  rescue IPAddr::InvalidAddressError
    # skip if CIDR is malformed
  end
end
