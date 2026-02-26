class AgentsController < ApplicationController
  skip_before_action :verify_authenticity_token

  # GET /agents
  def index
    @agents = Agent.all.order(created_at: :desc)
  end

  # POST /agents
  def create
    agent = Agent.create!
    redirect_to download_agent_path(agent)
  rescue => e
    redirect_to agents_path, alert: "Failed to create agent: #{e.message}"
  end

  # DELETE /agents/:id
  def destroy
    agent = Agent.find(params[:id])
    agent.destroy
    redirect_to agents_path
  rescue => e
    redirect_to agents_path, alert: "Failed to delete agent: #{e.message}"
  end

  # GET /agents/:id/download
  def download
    agent = Agent.find(params[:id])

    temp_dir = "/tmp/agent-#{agent.agent_id}"
    FileUtils.mkdir_p(temp_dir)

    # Write agent script
    server_ip = "100.69.88.107"
    script = generate_agent_script(agent, server_ip)
    File.write("#{temp_dir}/scanner_agent.py", script)
    File.chmod(0755, "#{temp_dir}/scanner_agent.py")

    # Write SSH private key
    File.write("#{temp_dir}/agent_key", agent.ssh_private_key)
    File.chmod(0600, "#{temp_dir}/agent_key")

    # Write SSH public key (for server setup reference)
    File.write("#{temp_dir}/agent_key.pub", agent.ssh_public_key)

    # Write install script
    install_script = <<~BASH
      #!/bin/bash
      chmod 600 agent_key
      chmod +x scanner_agent.py
      echo "✅ Agent ready!"
      echo "   Run: ./scanner_agent.py"
    BASH
    File.write("#{temp_dir}/install.sh", install_script)
    File.chmod(0755, "#{temp_dir}/install.sh")

    # Write README
    readme = <<~README
      SCANNER AGENT - INSTALLATION
      ============================

      Customer Instructions:
      1. Run: ./install.sh
      2. Run: ./scanner_agent.py
      3. Keep the script running (it will auto-reconnect if disconnected)

      What This Does:
      - Creates a secure tunnel to the scanner server
      - Allows scanning of your internal network without VPN
      - No incoming connections - only outbound SSH
      - All traffic encrypted via SSH

      Requirements:
      - Python 3.x
      - SSH client (usually pre-installed)

      To stop: Press Ctrl+C
    README
    File.write("#{temp_dir}/README.txt", readme)

    # Create ZIP
    require 'zip'
    zip_path = "/tmp/scanner-agent-#{agent.agent_id}.zip"

    Zip::File.open(zip_path, create: true) do |zipfile|
      Dir["#{temp_dir}/*"].each do |file|
        zipfile.add(File.basename(file), file)
      end
    end

    # Send file - OS will clean up /tmp/ automatically
    send_file zip_path,
              filename: "scanner-agent-#{agent.agent_id}.zip",
              type: 'application/zip',
              disposition: 'attachment'
  end

  # POST /agents/:agent_id/heartbeat
  def heartbeat
    agent = Agent.find_by!(agent_id: params[:agent_id])

    update_params = { last_seen: Time.current, status: 'connected' }
    update_params[:platform] = params[:platform] if params[:platform].present?
    update_params[:hostname] = params[:hostname] if params[:hostname].present?

    agent.update!(update_params)

    render json: { success: true, agent_id: agent.agent_id, last_seen: agent.last_seen }
  rescue ActiveRecord::RecordNotFound
    render json: { error: 'Agent not found' }, status: 404
  rescue => e
    render json: { error: e.message }, status: 500
  end

  private

  def generate_agent_script(agent, server_ip)
    <<~PYTHON
#!/usr/bin/env python3
import subprocess
import time
import sys
import os
import socket
import select
import threading
import struct

AGENT_ID        = "#{agent.agent_id}"
TUNNEL_SERVER   = "#{server_ip}"       # SSH tunnel destination
RAILS_SERVER    = "#{server_ip}:3000"  # Rails app for heartbeats
TUNNEL_PORT     = #{agent.tunnel_port}
SSH_KEY_FILE    = "./agent_key"
SOCKS_PORT      = 1080
HEARTBEAT_INTERVAL = 60

class SimpleSocks5Server:
    """Minimal SOCKS5 proxy server for network scanning"""

    def __init__(self, host='127.0.0.1', port=SOCKS_PORT):
        self.host = host
        self.port = port
        self.server = None

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(100)
        print(f"SOCKS5 proxy listening on {self.host}:{self.port}")

        while True:
            try:
                client, addr = self.server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client,))
                thread.daemon = True
                thread.start()
            except Exception as e:
                print(f"SOCKS error: {e}")
                break

    def handle_client(self, client):
        try:
            client.recv(262)
            client.sendall(b"\\x05\\x00")

            data = client.recv(4)
            if len(data) < 4:
                return

            mode = data[1]
            if mode != 1:
                return

            addrtype = data[3]

            if addrtype == 1:
                addr = socket.inet_ntoa(client.recv(4))
            elif addrtype == 3:
                addr_len = client.recv(1)[0]
                addr = client.recv(addr_len).decode()
            else:
                return

            port = struct.unpack('>H', client.recv(2))[0]

            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((addr, port))

                bind_addr = remote.getsockname()
                addr_bytes = socket.inet_aton(bind_addr[0])
                port_bytes = struct.pack('>H', bind_addr[1])
                client.sendall(b"\\x05\\x00\\x00\\x01" + addr_bytes + port_bytes)

                self.forward_data(client, remote)
            except Exception:
                client.sendall(b"\\x05\\x05\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        except Exception:
            pass
        finally:
            client.close()

    def forward_data(self, client, remote):
        while True:
            r, w, e = select.select([client, remote], [], [], 1)
            if client in r:
                data = client.recv(4096)
                if not data:
                    break
                remote.sendall(data)
            if remote in r:
                data = remote.recv(4096)
                if not data:
                    break
                client.sendall(data)

def start_socks_server():
    socks = SimpleSocks5Server()
    thread = threading.Thread(target=socks.start)
    thread.daemon = True
    thread.start()
    time.sleep(1)

def send_heartbeat():
    import urllib.request
    import json
    import platform
    url = f"http://{RAILS_SERVER}/agents/{AGENT_ID}/heartbeat"
    data = json.dumps({
        "platform": platform.system(),
        "hostname": platform.node()
    }).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass  # Don't crash if heartbeat fails

def heartbeat_loop():
    while True:
        send_heartbeat()
        time.sleep(HEARTBEAT_INTERVAL)

def create_tunnel():
    print(f"Connecting tunnel to {TUNNEL_SERVER}:{TUNNEL_PORT}...")

    cmd = [
        "ssh",
        "-i", SSH_KEY_FILE,
        "-R", f"{TUNNEL_PORT}:localhost:{SOCKS_PORT}",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ServerAliveInterval=60",
        "-N",
        f"agent@{TUNNEL_SERVER}"
    ]

    return subprocess.Popen(cmd)

def main():
    print("=" * 60)
    print("SCANNER AGENT")
    print("=" * 60)
    print(f"Agent ID:      {AGENT_ID}")
    print(f"Server:        {TUNNEL_SERVER}")
    print(f"Tunnel Port:   {TUNNEL_PORT}")
    print("=" * 60)

    if not os.path.exists(SSH_KEY_FILE):
        print(f"ERROR: SSH key not found: {SSH_KEY_FILE}")
        sys.exit(1)

    os.chmod(SSH_KEY_FILE, 0o600)

    print("Starting SOCKS5 proxy server...")
    start_socks_server()

    print("Starting heartbeat...")
    hb = threading.Thread(target=heartbeat_loop)
    hb.daemon = True
    hb.start()

    tunnel_process = None
    while True:
        try:
            tunnel_process = create_tunnel()
            print("Tunnel established. Press Ctrl+C to stop.")
            tunnel_process.wait()

        except KeyboardInterrupt:
            print("\\nShutting down...")
            if tunnel_process:
                tunnel_process.terminate()
            sys.exit(0)

        except Exception as e:
            print(f"Error: {e}")

        print("Reconnecting in 10 seconds...")
        time.sleep(10)

if __name__ == "__main__":
    main()
    PYTHON
  end
end
