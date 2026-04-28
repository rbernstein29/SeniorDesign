# Detects exploit/auxiliary success from msfconsole output.
#
# Two output sources hit the same regexes today (RPC console reads + PTY
# subprocess captures), so this collapses both into one parser. Subprocess
# output should already be ANSI-stripped before being passed in.
module Aegis
  module Msf
    module OutputParser
      module_function

      # Auxiliary / safe-mode scan: success when the output contains either an
      # explicit [+] hit line or a [*] target_ip line that isn't the generic
      # "Scanned X of Y hosts" progress noise.
      def parse_safe_mode(output, target_ip)
        ip_pat = Regexp.escape(target_ip)
        meaningful_ip_lines = output.scan(/\[\*\] #{ip_pat}.+/i)
                                    .reject { |l| l.match?(/Scanned \d+ of \d+ hosts/i) }
        success  = output.match?(/\[\+\]/i) || meaningful_ip_lines.any?
        evidence = (output.scan(/\[\+\].+/i) + meaningful_ip_lines).map(&:strip).join("\n").first(500)
        { success: success, evidence: evidence.presence, meaningful_ip_lines: meaningful_ip_lines }
      end

      # Exploit subprocess: success only when an actual session opens. Evidence
      # is the [+] lines plus any "session N opened" line, capped at 500 chars.
      def parse_exploit_mode(output)
        success = output.match?(/session \d+ opened|Meterpreter session|Command shell session/i)
        evidence_lines = output.scan(/\[\+\].*|.*session \d+ opened.*/i).join("\n")
        evidence = evidence_lines.length > 500 ? evidence_lines[0, 500] : evidence_lines
        { success: success, evidence: evidence.presence }
      end
    end
  end
end
