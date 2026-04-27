namespace :db do
  desc "Truncate all vuln_scanner tables and restart their sequences (dev only — never run in production)"
  task truncate: :environment do
    raise "Refusing to truncate in production!" if Rails.env.production?

    tables = %w[
      findings
      scan_exploits
      scan_targets
      scans
      reports
      assets
      sites
      agents
      sessions
      scan_profiles
      users
      organizations
      exploits
      operating_systems
      exploit_os_compatibility
      asset_use_cases
      exploit_use_case_relevance
    ]

    conn = ActiveRecord::Base.connection

    tables.each do |table|
      full = "vuln_scanner.#{table}"
      conn.execute("TRUNCATE #{full} RESTART IDENTITY CASCADE")
      puts "  truncated #{full}"
    rescue ActiveRecord::StatementInvalid => e
      puts "  skipped #{full}: #{e.message.split("\n").first}"
    end

    puts "\nDone. All vuln_scanner tables cleared."
  end
end
