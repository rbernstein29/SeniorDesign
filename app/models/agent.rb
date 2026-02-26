class Agent < ApplicationRecord
  before_create :generate_credentials
  # No key deployment needed — SSH queries keys directly from the database
  # via AuthorizedKeysCommand on the server (see /usr/local/bin/ssh_authorized_keys)

  # Check if connected (last heartbeat within 2 minutes)
  def connected?
    last_seen.present? && last_seen > 2.minutes.ago
  end
  
  # Update heartbeat
  def heartbeat!
    update!(last_seen: Time.current, status: 'connected')
  end
  
  # Get package config
  def package_config
    {
      agent_id: agent_id,
      scanner_server: ENV.fetch('SCANNER_SERVER_IP', 'localhost'),
      tunnel_port: tunnel_port,
      ssh_private_key: ssh_private_key
    }
  end
  
  private

  def generate_credentials
    # Generate UUID
    self.agent_id = SecureRandom.uuid
    
    # Assign random port
    used_ports = Agent.pluck(:tunnel_port).compact
    self.tunnel_port = (9000..9999).to_a.sample(100).find { |p| !used_ports.include?(p) } || 9000
    
    # Generate SSH keys
    keys = generate_ssh_keys
    self.ssh_private_key = keys[:private_key]
    self.ssh_public_key = keys[:public_key]
    self.ssh_key_fingerprint = keys[:fingerprint]
  end
  
  def generate_ssh_keys
    require 'open3'
    
    temp_path = "/tmp/agent_key_#{SecureRandom.hex(8)}"
    
    # Generate SSH key
    cmd = "ssh-keygen -t rsa -b 4096 -f #{temp_path} -N '' -C 'agent-#{agent_id}'"
    stdout, stderr, status = Open3.capture3(cmd)
    
    raise "SSH key generation failed: #{stderr}" unless status.success?
    
    # Read keys
    private_key = File.read(temp_path)
    public_key = File.read("#{temp_path}.pub")
    
    # Get fingerprint
    fingerprint_cmd = "ssh-keygen -lf #{temp_path}.pub"
    fingerprint_output, = Open3.capture2(fingerprint_cmd)
    fingerprint = fingerprint_output.split[1]
    
    # Clean up
    File.delete(temp_path)
    File.delete("#{temp_path}.pub")
    
    {
      private_key: private_key,
      public_key: public_key.strip,
      fingerprint: fingerprint
    }
  end
end