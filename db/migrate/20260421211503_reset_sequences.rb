class ResetSequences < ActiveRecord::Migration[8.0]
  TABLES = %w[
    scans reports findings scan_exploits scan_targets
    exploits assets organizations users agents sites sessions
    scan_profiles asset_use_cases exploit_os_compatibility
    exploit_use_case_relevance operating_systems use_cases
  ].freeze

  def up
    TABLES.each do |table|
      begin
        execute <<~SQL
          SELECT setval(
            pg_get_serial_sequence('vuln_scanner.#{table}', 'id'),
            COALESCE((SELECT MAX(id) FROM vuln_scanner.#{table}), 1)
          )
        SQL
      rescue => e
        Rails.logger.warn "reset_sequences: skipping #{table} — #{e.message}"
      end
    end
  end

  def down
    # sequences cannot be meaningfully reversed
  end
end
