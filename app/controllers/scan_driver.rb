# driver.rb: This file is responsible for executing the scans and exploits on a network
require 'json'
require 'socket'
require 'msfrpc-client'
require 'timeout'
require 'net/smtp'
require_relative '../../db/db_driver'

# Connect to the organization network from an IP or domain.
#
# Parameters:
#   String ip: the IP of the target network
#
# Returns:
#   1: succcessful connection
#   Error: connection unsuccessful

def connect_network(ip)
    begin
        puts "Connecting to network at #{ip}..."
        # Simple connectivity check (TCP connect to port 80)
        Socket.tcp(ip, 80, connect_timeout: 5) {}
        puts "Connection successful."
        return 1
    rescue Errno::ECONNREFUSED
        puts "Connection refused (host up)."
        return 1
    rescue => e
        puts "Connection failed: #{e.message}"
        return e
    end
end


# Disconnect from all current networks
#
# Returns:
#   1: successfully disconnected
#   Error: disconnection unsuccessful

def disconnect_network()
    puts "Disconnecting from network..."
    # Placeholder for cleanup logic (e.g. closing tunnels)
    return 1
end


# Attacks a system vulnerability using a Metasploit exploit
#
# Parameters:
#   Exploit exploit: Metasploit exploit to attempt on the vulernability
#   String target_ip: The target IP address
#   Integer port: The target port number
#
# Returns:
#   1: exploit successful
#   0: exploit unsuccessful

def attack(exploit, target_ip, port)
    puts "Attacking #{target_ip}:#{port} with exploit: #{exploit['name']}..."

    begin
        Timeout.timeout(60) do
            # Connect to Metasploit RPC
            rpc = Msf::RPC::Client.new(
                host: ENV.fetch('MSF_HOST', '127.0.0.1'),
                port: ENV.fetch('MSF_PORT', '55553').to_i,
                ssl:  ENV.fetch('MSF_SSL', 'true') == 'true',
                user: ENV.fetch('MSF_USER', 'msf'),
                pass: ENV.fetch('MSF_PASS', 'password')
            )

            # Execute the module
            res = rpc.call('module.execute', 'exploit', exploit['metasploit_module'], {
                'RHOSTS' => target_ip,
                'RPORT' => port.to_s
            })

            puts "Exploit launched (Job ID: #{res['job_id']}). Waiting for session..."
            
            # Wait for potential session creation
            sleep(5)
            sessions = rpc.call('session.list')
            
            # Check if a session was established for the target
            session_pair = sessions.find { |id, s| s['target_host'] == target_ip }
            
            if session_pair
                session_id = session_pair[0]
                puts "Exploit successful! Session established (ID: #{session_id})."
                details = get_session_details(rpc, session_id)
                puts "Session Info: #{details['info']}" if details
                return 1
            else
                puts "Exploit unsuccessful (no session)."
                return 0
            end
        end
    rescue Timeout::Error
        puts "Attack timed out."
        return 0
    rescue => e
        puts "Attack failed: #{e.message}"
        return 0
    end
end


# Retrieve details for a specific session
#
# Parameters:
#   Object rpc: The Metasploit RPC client
#   String session_id: The ID of the session
#
# Returns:
#   Hash: The session details

def get_session_details(rpc, session_id)
    sessions = rpc.call('session.list')
    return sessions[session_id.to_s]
rescue => e
    puts "Error getting session details: #{e.message}"
    return nil
end


# Convert the results of a scan into a json string
#
# Parameters:
#   results_raw: the results of the scan
#
# Returns:
#   String results: the JSON string of the results

def result_to_json(results_raw)
    JSON.generate(results_raw)
rescue JSON::GeneratorError => e
    puts "JSON Generation Error: #{e.message}"
end


# Log scan results to a local file
#
# Parameters:
#   String results_json: The JSON string of the results
#   Integer org_id: The organization ID

def log_results_to_file(results_json, org_id)
    log_dir = "logs"
    Dir.mkdir(log_dir) unless Dir.exist?(log_dir)

    filename = "#{log_dir}/scan_results_org_#{org_id}_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
    File.write(filename, results_json)
    puts "Results logged to #{filename}"
rescue => e
    puts "Failed to log results to file: #{e.message}"
end


# Clean up log files older than a specified number of days
#
# Parameters:
#   Integer days: The age in days to determine which files to delete (default: 7)

def cleanup_old_logs(days = 7)
    log_dir = "logs"
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


# Call the metasploit framework
#
# Parameters:
#   int exploit_id: the id of the desired exploit
#
# Returns:
#   Exploit exploit: the desired exploit from the Metasploit framework

def get_exploit(exploit_id)
    conn = get_connection
    return nil unless conn

    begin
        # Using 'vuln_scanner' schema as defined in schema.rb
        result = conn.exec_params(
            "SELECT * FROM vuln_scanner.exploits WHERE id = $1",
            [exploit_id]
        )
        conn.close
        return result.ntuples > 0 ? result.first : nil
    rescue PG::Error => e
        puts "Error fetching exploit: #{e.message}"
        conn&.close
        return nil
    end
end


# Retrieve list of target IPs for an organization
#
# Parameters:
#   int org_id: the organization ID
#
# Returns:
#   Array: list of hashes containing IP addresses and ports

def get_targets(org_id)
    conn = get_connection
    return [] unless conn

    begin
        result = conn.exec_params(
            "SELECT ip_address, ports FROM vuln_scanner.assets WHERE org_id = $1 AND is_active = true",
            [org_id]
        )
        conn.close
        
        targets = []
        result.each do |row|
            # Parse Postgres array format "{80,443}" or default to 80
            ports_raw = row['ports']
            ports = if ports_raw && ports_raw.start_with?('{')
                        ports_raw.tr('{}', '').split(',').map(&:to_i)
                    else
                        [80]
                    end
            targets << { 'ip' => row['ip_address'], 'ports' => ports }
        end
        return targets
    rescue PG::Error => e
        puts "Error fetching targets: #{e.message}"
        conn&.close
        return []
    end
end


# Retrieve admin email for an organization
#
# Parameters:
#   int org_id: the organization ID
#
# Returns:
#   String: the admin email address

def get_admin_email(org_id)
    conn = get_connection
    return nil unless conn

    begin
        result = conn.exec_params(
            "SELECT email FROM vuln_scanner.users WHERE org_id = $1 AND access_level = 'admin' LIMIT 1",
            [org_id]
        )
        conn.close
        return result.ntuples > 0 ? result.first['email'] : nil
    rescue PG::Error => e
        puts "Error fetching admin email: #{e.message}"
        conn&.close
        return nil
    end
end


# Send email notification
#
# Parameters:
#   String to_email: recipient email
#   String subject: email subject
#   String body: email body

def send_email(to_email, subject, body)
    from_email = ENV.fetch('SMTP_FROM', 'scanner@example.com')
    smtp_host = ENV.fetch('SMTP_HOST', 'localhost')
    smtp_port = ENV.fetch('SMTP_PORT', '25').to_i

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


# Main body of the scan_driver. Responsible for running the scans and exploits

def main
    org_id = 1
    schema = "vuln_scanner"

    puts "Starting Scan..."
    targets = get_targets(org_id)
    results = []
    threads = []
    mutex = Mutex.new
    
    targets.each do |target|
        target_ip = target['ip']
        target_ports = target['ports']

        threads << Thread.new do
            begin
                if connect_network(target_ip) == 1
                    target_ports.each do |port|
                        # Example: Run exploits with IDs 1 to 5
                        (1..5).each do |id|
                            exploit = get_exploit(id)
                            next unless exploit
                            
                            outcome = attack(exploit, target_ip, port)
                            mutex.synchronize do
                                results << {
                                    target: target_ip,
                                    port: port,
                                    exploit: exploit['name'],
                                    success: outcome == 1,
                                    timestamp: Time.now
                                }
                            end
                        end
                    end
                    
                    disconnect_network()
                else
                    puts "Could not connect to target #{target_ip}."
                end
            rescue => e
                puts "Error scanning target #{target_ip}: #{e.message}"
            end
        end
    end

    threads.each(&:join)

    report_json = result_to_json(results)
    write_report(report_json, org_id, schema)
    log_results_to_file(report_json, org_id)
    cleanup_old_logs(7)
    
    admin_email = get_admin_email(org_id)
    if admin_email
        send_email(admin_email, "Scan Report for Org #{org_id}", report_json)
    else
        puts "No admin email found for organization #{org_id}"
    end
    
    puts "Scan complete."
end
