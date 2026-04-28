# Queues a re-test ScanJob for every finding in a report. Returns a Result so
# the calling controller (web or API) can render its native response idiom.
module Aegis
  module Reports
    class Retester
      Result = Struct.new(:queued, :asset_count, :module_count, :error, keyword_init: true) do
        def queued?  = queued
      end

      def initialize(report, organization_id:, user_id:)
        @report          = report
        @organization_id = organization_id
        @user_id         = user_id
      end

      def call
        scan     = @report.scan
        findings = Finding.where(scan_id: @report.scan_id).includes(:exploit, :asset)

        asset_ids        = findings.map(&:asset_id).uniq.compact
        module_allowlist = findings.map { |f| f.exploit&.metasploit_module }.uniq.compact

        if asset_ids.empty? || module_allowlist.empty?
          return Result.new(queued: false, error: 'No findings to retest')
        end

        ScanJob.perform_later(
          @organization_id,
          { 'module_allowlist' => module_allowlist },
          @user_id,
          asset_ids,
          { safe_mode: scan&.safe_mode?, retest_of: scan&.id }
        )

        Result.new(queued: true, asset_count: asset_ids.size, module_count: module_allowlist.size)
      end
    end
  end
end
