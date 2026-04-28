# Activity-log notifications for scan lifecycle events.
# Same writes used to live inline in ScanJob and ScanService — consolidating
# them here keeps the wording, color, and rescue-nil semantics in one spot
# so future tweaks (e.g. adding a notification channel) only touch one file.
module Aegis
  module Notifications
    module ScanLifecycle
      module_function

      def started(scan, target_count, organization_id:, user_id:)
        log(
          organization_id: organization_id,
          user_id:         user_id,
          color:           'cyan',
          text:            "Scan <strong>#{h(scan&.scan_name)}</strong> started on #{target_count} target(s)"
        )
      end

      def completed(scan, findings_count, organization_id:, user_id:)
        log(
          organization_id: organization_id,
          user_id:         user_id,
          color:           'green',
          text:            "Scan <strong>#{h(scan&.scan_name)}</strong> completed — #{findings_count} finding(s)"
        )
      end

      # Optional `message` is an error string included in the activity entry.
      # ScanJob includes it; ScanService omits it (its rescue logs the error
      # via puts and the job's outer rescue captures the same exception).
      def failed(scan, organization_id:, user_id:, message: nil)
        text = "Scan <strong>#{h(scan&.scan_name || 'scan')}</strong> failed"
        text += ": #{h(message.to_s.truncate(80))}" if message.present?
        log(
          organization_id: organization_id,
          user_id:         user_id,
          color:           'red',
          text:            text
        )
      end

      def log(**attrs)
        ActivityLog.create!(**attrs)
      rescue
        nil
      end

      def h(value)
        ERB::Util.h(value.to_s)
      end
    end
  end
end
