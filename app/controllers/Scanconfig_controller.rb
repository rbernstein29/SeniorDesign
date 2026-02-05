class ScansconfigController < ApplicationController
  # Show the scan configuration form
  def new
    # Just renders the form
  end

  # Handle form submission
  def create
    # Get all the form data
    @scan_config = params.permit(
      :scan_mode,
      :scope,
      :network,
      :exclude,
      :port,
      :os,
      :asset,
      :scan_type,
      :credential,
      :schedule,
      :cve,
      format: []  # Array for checkboxes
    )

    # For now, display what was received
    render plain: <<~TEXT
      ✓ Scan Configuration Received!
      
      SCAN SETTINGS:
      - Scan Mode: #{@scan_config[:scan_mode]}
      - Target Scope: #{@scan_config[:scope]}
      - Network Range: #{@scan_config[:network]}
      - Exclude Network: #{@scan_config[:exclude]}
      - Port Range: #{@scan_config[:port]}
      - OS: #{@scan_config[:os]}
      - Asset Type: #{@scan_config[:asset]}
      - Scan Type: #{@scan_config[:scan_type]}
      - Credential: #{@scan_config[:credential]}
      - Schedule: #{@scan_config[:schedule]}
      - CVE ID: #{@scan_config[:cve]}
      - Report Formats: #{@scan_config[:format]&.join(', ')}
      
      Next: This data will be saved and scan will be triggered.
    TEXT
  end
end