class AgentsController < ApplicationController
  skip_before_action :verify_authenticity_token  # For now, disable CSRF
  
  # POST /agents - Create new agent
  def create
    agent = Agent.create!
    
    render json: {
      id: agent.id,
      agent_id: agent.agent_id,
      tunnel_port: agent.tunnel_port,
      status: 'created'
    }
  rescue => e
    render json: { error: e.message }, status: 500
  end
  
  # DELETE /agents/:id
  def destroy
    agent = Agent.find(params[:id])
    agent.destroy
    
    render json: { success: true }
  rescue => e
    render json: { error: e.message }, status: 404
  end
  
  # GET /agents/:id/download
  def download
    agent = Agent.find(params[:id])
    
    # Create temp directory
    temp_dir = "/tmp/agent-#{agent.agent_id}"
    FileUtils.mkdir_p(temp_dir)
    
    # Write agent script
    script = generate_agent_script(agent)
    File.write("#{temp_dir}/scanner_agent.py", script)
    File.chmod("#{temp_dir}/scanner_agent.py", 0755)
    
    # Write SSH key
    File.write("#{temp_dir}/agent_key", agent.ssh_private_key)
    File.chmod("#{temp_dir}/agent_key", 0600)
    
    # Write install script
    install_script = <<~BASH
      #!/bin/bash
      chmod 600 agent_key
      chmod +x scanner_agent.py
      echo "✅ Ready! Run: ./scanner_agent.py"
    BASH
    File.write("#{temp_dir}/install.sh", install_script)
    File.chmod("#{temp_dir}/install.sh", 0755)
    
    # Create ZIP
    require 'zip'
    zip_path = "/tmp/scanner-agent-#{agent.agent_id}.zip"
    
    Zip::File.open(zip_path, Zip::File::CREATE) do |zipfile|
      Dir["#{temp_dir}/*"].each do |file|
        zipfile.add(File.basename(file), file)
      end
    end
    
    # Send file
    send_file zip_path,
              filename: "scanner-agent-#{agent.agent_id}.zip",
              type: 'application/zip',
              disposition: 'attachment'
    
    # Clean up
    FileUtils.rm_rf(temp_dir)
    File.delete(zip_path) if File.exist?(zip_path)
  end
  
  private
  
  def generate_agent_script(agent)
    server_ip = ENV.fetch('SCANNER_SERVER_IP', 'localhost')
    
    <<~PYTHON
#!/usr/bin/env python3
import subprocess
import time
import sys
import os

AGENT_ID = "#{agent.agent_id}"
SCANNER_SERVER = "#{server_ip}"
TUNNEL_PORT = #{agent.tunnel_port}
SSH_KEY_FILE = "./agent_key"

def create_tunnel():
    print(f"🔗 Creating tunnel to {SCANNER_SERVER}:{TUNNEL_PORT}...")
    
    cmd = [
        "ssh",
        "-i", SSH_KEY_FILE,
        "-R", f"{TUNNEL_PORT}:localhost:22",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=60",
        "-N",
        f"agent@{SCANNER_SERVER}"
    ]
    
    return subprocess.Popen(cmd)

def main():
    print("=" * 60)
    print("🛡️  SCANNER AGENT")
    print("=" * 60)
    print(f"Agent ID:      {AGENT_ID}")
    print(f"Scanner:       {SCANNER_SERVER}")
    print(f"Tunnel Port:   {TUNNEL_PORT}")
    print("=" * 60)
    
    if not os.path.exists(SSH_KEY_FILE):
        print(f"❌ SSH key not found: {SSH_KEY_FILE}")
        sys.exit(1)
    
    os.chmod(SSH_KEY_FILE, 0o600)
    
    while True:
        try:
            tunnel_process = create_tunnel()
            print("✅ Tunnel established!")
            print("   Press Ctrl+C to stop\\n")
            tunnel_process.wait()
            
        except KeyboardInterrupt:
            print("\\n🛑 Shutting down...")
            tunnel_process.terminate()
            sys.exit(0)
            
        except Exception as e:
            print(f"❌ Error: {e}")
        
        print("🔄 Reconnecting in 10 seconds...\\n")
        time.sleep(10)

if __name__ == "__main__":
    main()
    PYTHON
  end
end