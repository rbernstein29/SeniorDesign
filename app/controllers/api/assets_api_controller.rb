module Api
  class AssetsApiController < ApiController
    before_action :require_api_admin!, only: [:create, :destroy]

    def index
      org_assets = Asset.where(organization_id: @current_user.organization_id)
                        .order(created_at: :desc)
      cidr = params[:cidr].to_s.strip
      if cidr.present?
        require "ipaddr"
        begin
          range = IPAddr.new(cidr)
          count = org_assets.count { |a|
            range.include?(IPAddr.new(a.ip_address.to_s.split("/").first)) rescue false
          }
          render json: { count: count } and return
        rescue IPAddr::InvalidAddressError
          render json: { error: "Invalid CIDR" }, status: :unprocessable_entity and return
        end
      end
      render json: { assets: org_assets.map { |a| asset_json(a) } }
    end

    def show
      asset = Asset.where(organization_id: @current_user.organization_id).find(params[:id])
      asset_scan_ids = Finding.where(asset_id: asset.id).distinct.pluck(:scan_id)
      last_scan      = Scan.where(id: asset_scan_ids).order("end_time desc nulls last").first
      findings_count = Finding.where(asset_id: asset.id).count
      render json: {
        asset:          asset_json(asset),
        last_scan:      last_scan ? scan_brief_json(last_scan) : nil,
        findings_count: findings_count
      }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Asset not found" }, status: :not_found
    end

    # Body: network (IP, CIDR ≥/24, or hostname), hostname, site_id,
    #       port, os, asset_type, criticality, notes
    def create
      network     = params[:network].to_s.strip
      hostname    = params[:hostname].presence
      site_id     = params[:site_id].presence
      scan_config = {
        "port"       => params[:port].presence,
        "os"         => params[:os].presence,
        "asset_type" => params[:asset_type].presence
      }.compact
      criticality = params[:criticality].presence || "unknown"
      notes       = params[:notes].presence

      ips = expand_targets(network)
      if ips.empty?
        render json: { error: "Invalid target: '#{network}'" }, status: :unprocessable_entity
        return
      end

      created_assets = []
      ips.each do |ip|
        asset = Asset.create!(
          ip_address:      ip,
          organization_id: @current_user.organization_id,
          site_id:         site_id,
          scan_config:     scan_config,
          hostname:        hostname,
          criticality:     criticality,
          notes:           notes
        )
        DnsLookupJob.perform_later(asset.id) unless hostname.present?
        created_assets << asset
      end
      render json: { created: created_assets.size, assets: created_assets.map { |a| asset_json(a) } },
             status: :created
    rescue => e
      render json: { error: e.message }, status: :unprocessable_entity
    end

    def destroy
      asset = Asset.where(organization_id: @current_user.organization_id).find(params[:id])
      asset.destroy
      render json: { deleted: true, id: params[:id].to_i }
    rescue ActiveRecord::RecordNotFound
      render json: { error: "Asset not found" }, status: :not_found
    end

    private

    def asset_json(a)
      {
        id:          a.id,
        ip_address:  a.ip_address.to_s,
        hostname:    a.hostname,
        domain:      a.domain,
        criticality: a.criticality,
        notes:       a.notes,
        site_id:     a.site_id,
        scan_config: a.scan_config,
        is_active:   a.is_active,
        created_at:  a.created_at
      }
    end

    def scan_brief_json(s)
      { id: s.id, status: s.status, end_time: s.end_time, findings_count: s.findings_count }
    end

    def expand_targets(network)
      require "ipaddr"
      addr = IPAddr.new(network)
      if !network.include?("/") || addr.prefix == 32
        [addr.to_s]
      else
        raise "Range too large — use /24 or smaller" if addr.prefix < 24
        addr.to_range.to_a[1..-2].map(&:to_s)
      end
    rescue IPAddr::InvalidAddressError
      []
    end
  end
end
