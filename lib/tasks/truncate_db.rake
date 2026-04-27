namespace :db do
  desc "Truncate all vuln_scanner tables and restart their sequences (dev only — never run in production)"
  task truncate: :environment do
    raise "Refusing to truncate in production!" if Rails.env.production?

    conn = ActiveRecord::Base.connection

    skip = %w[schema_migrations ar_internal_metadata]

    tables = conn.execute(
      "SELECT tablename FROM pg_tables WHERE schemaname = 'vuln_scanner' ORDER BY tablename"
    ).map { |r| r["tablename"] }.reject { |t| skip.include?(t) }

    tables.each do |table|
      full = "vuln_scanner.#{table}"
      conn.execute("TRUNCATE #{full} RESTART IDENTITY CASCADE")
      puts "  truncated #{full}"
    rescue ActiveRecord::StatementInvalid => e
      puts "  skipped #{full}: #{e.message.split("\n").first}"
    end

    puts "\nDone. #{tables.size} tables cleared."
  end
end
