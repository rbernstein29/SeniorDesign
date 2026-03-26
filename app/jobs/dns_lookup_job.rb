class DnsLookupJob < ApplicationJob
  queue_as :default

  def perform(asset_id)
    asset = Asset.find_by(id: asset_id)
    return unless asset && asset.hostname.blank?

    ip = asset.ip_address.to_s.split('/').first
    result = Resolv.getname(ip) rescue nil
    asset.update!(hostname: result.presence || 'No Domain Name')
  end
end
