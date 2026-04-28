# Aegis runtime configuration.
#
# Centralizes every ENV.fetch the app needs. Loaded once at boot and frozen so
# values can't drift between callers. Read via Aegis.config.<group>.<key>.
#
# To override any value, set the corresponding ENV var (typically in .env).
# See .env.example for the full list and current defaults.

module Aegis
  Config = Struct.new(
    :msf, :agent, :ollama, :nvd, :smtp, :app, :scan,
    keyword_init: true
  )

  MsfConfig = Struct.new(
    :rpc_host, :rpc_port, :rpc_user, :rpc_pass, :rpc_ssl,
    :modules_path, :auxiliary_path, :console_path,
    :lhost, :lport, :debug,
    keyword_init: true
  )

  AgentConfig = Struct.new(
    :server_ip, :server_port, :socks_port,
    :heartbeat_interval, :http_timeout, :reconnect_backoff,
    :tunnel_port_min, :tunnel_port_max,
    keyword_init: true
  ) do
    def heartbeat_window      = heartbeat_interval.seconds
    def tunnel_port_range     = (tunnel_port_min..tunnel_port_max)
  end

  OllamaConfig = Struct.new(
    :host, :model, :read_timeout,
    :code_max_chars, :secure_code_max_chars, :system_prompt,
    keyword_init: true
  )

  NvdConfig = Struct.new(
    :url, :rate_limit_sleep, :max_per_request,
    keyword_init: true
  )

  SmtpConfig = Struct.new(:from, :host, :port, keyword_init: true)
  AppConfig  = Struct.new(:host, keyword_init: true)

  ScanConfig = Struct.new(
    :default_timeout,
    :tcp_probe_ports_direct, :tcp_probe_ports_proxy, :tcp_probe_timeout,
    :log_retention_days,
    keyword_init: true
  )

  class << self
    def config
      @config ||= build.freeze
    end

    private

    def build
      Config.new(
        msf:    build_msf,
        agent:  build_agent,
        ollama: build_ollama,
        nvd:    build_nvd,
        smtp:   build_smtp,
        app:    build_app,
        scan:   build_scan
      )
    end

    def build_msf
      default_modules = '/opt/metasploit-framework/embedded/framework/modules/exploits'
      apt_modules     = '/usr/share/metasploit-framework/modules/exploits'
      modules_path    = ENV['MSF_MODULES_PATH'].presence ||
                        (Dir.exist?(default_modules) ? default_modules : apt_modules)
      auxiliary_path  = ENV['MSF_AUXILIARY_PATH'].presence ||
                        modules_path.sub('/modules/exploits', '/modules/auxiliary')

      MsfConfig.new(
        rpc_host:       ENV.fetch('MSF_RPC_HOST', '127.0.0.1'),
        rpc_port:       ENV.fetch('MSF_RPC_PORT', '55553').to_i,
        rpc_user:       ENV.fetch('MSF_RPC_USER', 'msf'),
        rpc_pass:       ENV['MSF_RPC_PASS'],
        rpc_ssl:        truthy?(ENV.fetch('MSF_RPC_SSL', 'false')),
        modules_path:   modules_path,
        auxiliary_path: auxiliary_path,
        console_path:   detect_msfconsole_path,
        # lhost: nil when MSF_LHOST unset — caller auto-detects outbound IP.
        # When set, used verbatim (Docker scenarios).
        lhost:          ENV['MSF_LHOST'].presence,
        lport:          ENV.fetch('MSF_LPORT', '4444'),
        debug:          ENV.fetch('AEGIS_MSF_DEBUG', '1') == '1'
      ).freeze
    end

    def build_agent
      AgentConfig.new(
        server_ip:         ENV.fetch('SCANNER_SERVER_IP', 'localhost'),
        server_port:       ENV.fetch('AGENT_SERVER_PORT', '3000').to_i,
        socks_port:        ENV.fetch('AGENT_SOCKS_PORT', '1080').to_i,
        heartbeat_interval: ENV.fetch('AGENT_HEARTBEAT_INTERVAL', '30').to_i,
        http_timeout:      ENV.fetch('AGENT_HTTP_TIMEOUT', '10').to_i,
        reconnect_backoff: ENV.fetch('AGENT_RECONNECT_BACKOFF', '10').to_i,
        tunnel_port_min:   ENV.fetch('AGENT_TUNNEL_PORT_MIN', '9000').to_i,
        tunnel_port_max:   ENV.fetch('AGENT_TUNNEL_PORT_MAX', '9999').to_i
      ).freeze
    end

    def build_ollama
      OllamaConfig.new(
        host:                  ENV.fetch('OLLAMA_HOST', 'http://localhost:11434'),
        model:                 ENV.fetch('OLLAMA_MODEL', 'qwen2.5-coder:7b'),
        read_timeout:          ENV.fetch('OLLAMA_READ_TIMEOUT', '900').to_i,
        code_max_chars:        ENV.fetch('OLLAMA_CODE_MAX_CHARS', '30000').to_i,
        secure_code_max_chars: ENV.fetch('OLLAMA_SECURE_CODE_MAX_CHARS', '20000').to_i,
        system_prompt:         'You are a professional security auditor. Provide accurate, educational remediation and PoC exploits.'
      ).freeze
    end

    def build_nvd
      NvdConfig.new(
        url:              ENV.fetch('NVD_URL', 'https://services.nvd.nist.gov/rest/json/cves/2.0'),
        rate_limit_sleep: ENV.fetch('NVD_RATE_LIMIT_SLEEP', '0.25').to_f,
        max_per_request:  ENV.fetch('NVD_MAX_PER_REQUEST', '10').to_i
      ).freeze
    end

    def build_smtp
      SmtpConfig.new(
        from: ENV.fetch('SMTP_FROM', 'scanner@example.com'),
        host: ENV.fetch('SMTP_HOST', 'localhost'),
        port: ENV.fetch('SMTP_PORT', '25').to_i
      ).freeze
    end

    def build_app
      AppConfig.new(host: ENV.fetch('APP_HOST', 'localhost')).freeze
    end

    def build_scan
      ScanConfig.new(
        default_timeout:        ENV.fetch('SCAN_DEFAULT_TIMEOUT', '120').to_i,
        tcp_probe_ports_direct: parse_ports(ENV.fetch('SCAN_TCP_PROBE_PORTS_DIRECT', '22,80,443,445,8080')),
        tcp_probe_ports_proxy:  parse_ports(ENV.fetch('SCAN_TCP_PROBE_PORTS_PROXY', '22,80,443,445')),
        tcp_probe_timeout:      ENV.fetch('SCAN_TCP_PROBE_TIMEOUT', '5').to_i,
        log_retention_days:     ENV.fetch('SCAN_LOG_RETENTION_DAYS', '7').to_i
      ).freeze
    end

    def truthy?(value)
      value.to_s =~ /\A(t|y|1)/i ? true : false
    end

    def parse_ports(csv)
      csv.to_s.split(',').map { |p| p.strip.to_i }.select { |p| p > 0 }.freeze
    end

    def detect_msfconsole_path
      explicit = ENV['MSFCONSOLE_PATH']
      return explicit if explicit.present? && File.executable?(explicit)

      candidates = %w[
        /opt/metasploit-framework/bin/msfconsole
        /usr/bin/msfconsole
        /usr/local/bin/msfconsole
      ]
      candidates.find { |p| File.executable?(p) } || 'msfconsole'
    end
  end
end

Rails.logger&.info "[Aegis::Config] msf.modules_path=#{Aegis.config.msf.modules_path} app.host=#{Aegis.config.app.host}"
