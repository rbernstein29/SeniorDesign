class AssetsController < ApplicationController

  before_action :require_admin

  def index
    @assets = Asset.where(organization_id: current_org_id).order(created_at: :desc)
    if request.format.json?
      cidr = params[:cidr].to_s.strip
      count = 0
      if cidr.present?
        begin
          require 'ipaddr'
          range = IPAddr.new(cidr)
          count = Asset.where(organization_id: current_org_id).count { |a|
            range.include?(IPAddr.new(a.ip_address.to_s.split('/').first)) rescue false
          }
        rescue IPAddr::InvalidAddressError
          count = 0
        end
      end
      render json: { count: count }
    end
  end

  def new
    @sites = Site.where(organization_id: current_org_id)
  end

  def create
    network     = params[:network].to_s.strip
    hostname    = params[:hostname].presence
    site_id     = params[:site_id].presence
    scan_config = {
      'port'       => params[:port].presence,
      'os'         => params[:os].presence,
      'asset_type' => params[:asset_type].presence
    }.compact
    criticality = params[:criticality].presence || 'unknown'
    notes       = params[:notes].presence

    ips = expand_targets(network)

    if ips.empty?
      redirect_to new_asset_path, alert: "Invalid target: '#{network}'"
      return
    end

    created = 0
    ips.each do |ip|
      asset = Asset.create!(
        ip_address:      ip,
        organization_id: current_org_id,
        site_id:         site_id,
        scan_config:     scan_config,
        hostname:        hostname,
        criticality:     criticality,
        notes:           notes
      )
      DnsLookupJob.perform_later(asset.id) unless hostname.present?
      created += 1
    end

    redirect_to assets_path, notice: "#{created} asset(s) added."
  rescue => e
    redirect_to new_asset_path, alert: "Failed: #{e.message}"
  end

  def show
    @asset = Asset.where(organization_id: current_org_id).find(params[:id])
    asset_scan_ids  = Finding.where(asset_id: @asset.id).distinct.pluck(:scan_id)
    @last_scan      = Scan.where(id: asset_scan_ids).order('end_time desc nulls last').first
    @findings_count = Finding.where(asset_id: @asset.id).count
  rescue ActiveRecord::RecordNotFound
    redirect_to assets_path, alert: 'Asset not found'
  end

  def destroy
    asset = Asset.where(organization_id: current_org_id).find(params[:id])
    asset.destroy
    redirect_to assets_path, notice: 'Asset deleted.'
  rescue ActiveRecord::RecordNotFound
    redirect_to assets_path, alert: 'Asset not found'
  end

  private

  def expand_targets(network)
    require 'ipaddr'
    addr = IPAddr.new(network)
    if network.exclude?('/') || addr.prefix == 32
      [addr.to_s]
    else
      raise "Range too large — use /24 or smaller" if addr.prefix < 24
      addr.to_range.to_a[1..-2].map(&:to_s)
    end
  rescue IPAddr::InvalidAddressError
    []
  end
end
