# Parses Metasploit module .rb files for severity rank and metadata.
#
# Two metadata methods are provided to preserve historical behavior:
# - metadata_full: scan-time superset (handles %q{}, %q(), and quoted forms;
#   extracts disclosure date, authors, all reference types).
# - metadata_lite: the narrower regex set ExploitSyncJob has used since the
#   initial DB import — kept so re-syncs don't churn fields.
#
# Unifying the two is a deliberate behavior change for a separate task.
module Aegis
  module MsfModuleParser
    module_function

    # Match a Ruby-quoted string body, tracking the outer quote so embedded
    # quotes of the other style (e.g. 'Samba "username map script" Cmd Exec')
    # don't cut the capture short. Returns the inner body or nil.
    QUOTED_VALUE = /(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)")/.freeze

    def extract_quoted_value(content, key)
      m = content.match(/['"]#{Regexp.escape(key)}['"]\s*=>\s*#{QUOTED_VALUE}/m)
      return nil unless m
      (m[1] || m[2])&.gsub(/\\(['"\\])/, '\1')
    end

    SEVERITY_BY_RANK = {
      /excellent|great/ => 'critical',
      /good/            => 'high',
      /normal|average/  => 'medium'
    }.freeze

    def severity_from_rank(rank_word)
      r = rank_word.to_s.downcase
      SEVERITY_BY_RANK.each { |pat, sev| return sev if r.match?(pat) }
      'low'
    end

    def severity_from_file(path)
      content = File.read(path) rescue ''
      rank    = content.match(/\bRank\s*=\s*(\w+)/i)&.[](1)
      severity_from_rank(rank)
    end

    # Superset parser used by ScanService when materializing Exploit records
    # during a scan. Returns a hash with all fields populated where possible.
    def metadata_full(path)
      content = File.read(path) rescue ''

      name = extract_quoted_value(content, 'Name')&.strip

      desc = content.match(/'Description'\s*=>\s*%q[{(](.+?)[})]/m)&.[](1)
      desc ||= extract_quoted_value(content, 'Description')
      desc = desc&.gsub(/\s+/, ' ')&.strip

      raw_cve = content.match(/\[\s*['"]CVE['"]\s*,\s*['"]([^'"]+)['"]\s*\]/)&.[](1)
      cve_id  = raw_cve ? (raw_cve.start_with?('CVE') ? raw_cve : "CVE-#{raw_cve}") : nil

      refs = content.scan(/\[\s*['"](\w+)['"]\s*,\s*['"]([^'"]+)['"]\s*\]/)
                    .map { |type, val| { 'type' => type, 'value' => val } }

      raw_date        = extract_quoted_value(content, 'DisclosureDate')
      disclosure_date = raw_date ? (Date.parse(raw_date) rescue nil) : nil

      authors_block = content.match(/'Authors?'\s*=>\s*\[([^\]]+)\]/m)&.[](1)
      authors = authors_block&.scan(/['"]([^'"]+)['"]/)&.flatten&.join(', ')
      authors ||= extract_quoted_value(content, 'Author') || extract_quoted_value(content, 'Authors')

      { name: name, description: desc, cve_id: cve_id, references: refs,
        disclosure_date: disclosure_date, authors: authors }
    end

    # Subset parser used by ExploitSyncJob during bulk filesystem sync. Narrower
    # CVE/description regexes than metadata_full to match historical behavior.
    def metadata_lite(path, content: nil)
      content ||= File.read(path, encoding: 'utf-8', invalid: :replace, undef: :replace) rescue ''

      name = extract_quoted_value(content, 'Name')&.strip

      cve_m  = content.match(/\['CVE',\s*['"](\d{4}-\d+)['"]\]/)
      cve_id = cve_m ? "CVE-#{cve_m[1]}" : nil

      desc_m      = content.match(/'Description'\s*=>\s*%q(?:\{|\[|<)(.+?)(?:\}|\]|>)/m)
      description = desc_m ? desc_m[1].gsub(/\s+/, ' ').strip.truncate(500)
                            : extract_quoted_value(content, 'Description')&.gsub(/\s+/, ' ')&.strip&.truncate(500)

      rank_m   = content.match(/\bRank\s*=\s*(\w+)/i)
      severity = severity_from_rank(rank_m&.[](1))

      { name: name, description: description, cve_id: cve_id, severity: severity }
    end
  end
end
