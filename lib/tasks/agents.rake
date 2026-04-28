namespace :agents do
  desc "Deploy all agent public keys to the server's authorized_keys (dev only)"
  task sync_keys: :environment do
    agents = Agent.all
    if agents.empty?
      puts "No agents found."
      next
    end

    puts "🔑 Syncing #{agents.count} agent key(s) to server..."

    # Build the full authorized_keys content from all current agents
    keys_content = agents.map(&:ssh_public_key).join("\n") + "\n"

    # Write all keys to a temp file
    temp_file = "/tmp/agent_authorized_keys"
    File.write(temp_file, keys_content)

    # Deploy via scp + ssh (will prompt for trevor's password)
    server = Aegis.config.app.host
    user   = ENV.fetch('AGENT_DEPLOY_USER', 'trevor')

    puts "📤 Copying keys to #{server}... (you may be prompted for your password)"
    system("scp #{temp_file} #{user}@#{server}:/tmp/agent_authorized_keys")

    if $?.success?
      system("ssh #{user}@#{server} 'sudo cp /tmp/agent_authorized_keys /home/agent/.ssh/authorized_keys && sudo chmod 600 /home/agent/.ssh/authorized_keys && sudo chown agent:agent /home/agent/.ssh/authorized_keys'")
      puts $?.success? ? "✅ Keys deployed successfully!" : "❌ Failed to set permissions on server"
    else
      puts "❌ Failed to copy keys to server"
    end

    File.delete(temp_file)
  end

  desc "Show all agents and their connection status"
  task status: :environment do
    agents = Agent.all.order(created_at: :desc)

    puts "=" * 60
    puts "NETWORK AGENTS STATUS"
    puts "=" * 60

    if agents.empty?
      puts "No agents deployed yet."
      next
    end

    agents.each do |agent|
      status = agent.connected? ? "🟢 Connected" : "⚫ Offline"
      puts ""
      puts "Agent: #{agent.agent_id}"
      puts "  Status:   #{status}"
      puts "  Port:     #{agent.tunnel_port}"
      puts "  Platform: #{agent.platform || 'Unknown'}"
      puts "  Hostname: #{agent.hostname || 'Unknown'}"
      puts "  Last Seen: #{agent.last_seen || 'Never'}"
    end

    puts ""
    puts "=" * 60
  end
end
