require "test_helper"
require "zip"

class AgentZipBuilderTest < ActiveSupport::TestCase

  def setup
    @agent = agents(:agent_connected)
    @server_ip   = "10.0.0.1"
    @server_port = 3000
  end

  # ── build ─────────────────────────────────────────────────────────────────────

  test "build returns a string path ending in .zip" do
    zip_path = AgentZipBuilder.build(@agent, @server_ip, @server_port)
    assert_kind_of String, zip_path
    assert zip_path.end_with?(".zip"), "Expected zip path to end with .zip, got #{zip_path}"
  ensure
    FileUtils.rm_f(zip_path) if zip_path
  end

  test "build creates the zip file on disk" do
    zip_path = AgentZipBuilder.build(@agent, @server_ip, @server_port)
    assert File.exist?(zip_path), "Expected zip file to exist at #{zip_path}"
  ensure
    FileUtils.rm_f(zip_path) if zip_path
  end

  test "zip contains scanner_agent.py" do
    zip_path = AgentZipBuilder.build(@agent, @server_ip, @server_port)
    entries = zip_entry_names(zip_path)
    assert_includes entries, "scanner_agent.py"
  ensure
    FileUtils.rm_f(zip_path) if zip_path
  end

  test "zip contains SSH private key file" do
    zip_path = AgentZipBuilder.build(@agent, @server_ip, @server_port)
    entries = zip_entry_names(zip_path)
    assert_includes entries, "agent_key"
  ensure
    FileUtils.rm_f(zip_path) if zip_path
  end

  test "zip contains SSH public key file" do
    zip_path = AgentZipBuilder.build(@agent, @server_ip, @server_port)
    entries = zip_entry_names(zip_path)
    assert_includes entries, "agent_key.pub"
  ensure
    FileUtils.rm_f(zip_path) if zip_path
  end

  test "zip contains install.sh" do
    zip_path = AgentZipBuilder.build(@agent, @server_ip, @server_port)
    entries = zip_entry_names(zip_path)
    assert_includes entries, "install.sh"
  ensure
    FileUtils.rm_f(zip_path) if zip_path
  end

  test "zip contains README.txt" do
    zip_path = AgentZipBuilder.build(@agent, @server_ip, @server_port)
    entries = zip_entry_names(zip_path)
    assert_includes entries, "README.txt"
  ensure
    FileUtils.rm_f(zip_path) if zip_path
  end

  test "zip path includes agent_id" do
    zip_path = AgentZipBuilder.build(@agent, @server_ip, @server_port)
    assert_includes zip_path, @agent.agent_id
  ensure
    FileUtils.rm_f(zip_path) if zip_path
  end

  # ── generate_agent_script ─────────────────────────────────────────────────────

  test "generate_agent_script embeds agent_id" do
    script = AgentZipBuilder.generate_agent_script(@agent, @server_ip, @server_port)
    assert_includes script, @agent.agent_id
  end

  test "generate_agent_script embeds server IP" do
    script = AgentZipBuilder.generate_agent_script(@agent, @server_ip, @server_port)
    assert_includes script, @server_ip
  end

  test "generate_agent_script embeds tunnel port" do
    script = AgentZipBuilder.generate_agent_script(@agent, @server_ip, @server_port)
    assert_includes script, @agent.tunnel_port.to_s
  end

  test "generate_agent_script is valid Python (starts with shebang)" do
    script = AgentZipBuilder.generate_agent_script(@agent, @server_ip, @server_port)
    assert script.start_with?("#!/usr/bin/env python3")
  end

  test "generate_agent_script includes SOCKS5 proxy class" do
    script = AgentZipBuilder.generate_agent_script(@agent, @server_ip, @server_port)
    assert_includes script, "SimpleSocks5Server"
  end

  test "generate_agent_script includes heartbeat function" do
    script = AgentZipBuilder.generate_agent_script(@agent, @server_ip, @server_port)
    assert_includes script, "send_heartbeat"
  end

  private

  def zip_entry_names(zip_path)
    names = []
    Zip::File.open(zip_path) { |z| z.each { |e| names << e.name } }
    names
  end
end
