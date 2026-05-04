require "test_helper"
require "tmpdir"
require "scan_service"

class ScanServiceTest < ActiveSupport::TestCase
  def silence_stdout
    orig = $stdout
    $stdout = StringIO.new
    yield
  ensure
    $stdout = orig
  end

  def build(filter: {}, asset_ids: [], options: {}, scan: nil)
    ScanService.new(organizations(:acme).id, filter, users(:admin_user).id, scan, asset_ids, options)
  end

  # ── parse_ports / parse_port ──────────────────────────────────────────────

  test "parse_ports returns [nil] for blank input" do
    s = build
    assert_equal [nil], s.send(:parse_ports, nil)
    assert_equal [nil], s.send(:parse_ports, "")
    assert_equal [nil], s.send(:parse_ports, "   ")
  end

  test "parse_ports parses comma-separated and single ports" do
    s = build
    assert_equal [22, 80, 443], s.send(:parse_ports, "22,80,443")
    assert_equal [3306], s.send(:parse_ports, " 3306 ")
  end

  test "parse_ports filters out-of-range ports" do
    s = build
    parsed = s.send(:parse_ports, "0,80,99999")
    assert_equal [80], parsed
  end

  test "parse_ports falls back to random port when none valid" do
    s = build
    result = s.send(:parse_ports, "0,99999")
    assert_equal 1, result.size
    assert (1..65535).cover?(result.first)
  end

  test "parse_ports range syntax returns one random port in range" do
    s = build
    100.times do
      port = s.send(:parse_ports, "8000-8005").first
      assert (8000..8005).cover?(port), "expected port in range, got #{port}"
    end
  end

  test "parse_ports falls through to comma-split path for malformed ranges" do
    s = build
    # hi < lo: range-syntax check fails; comma-split treats whole string
    # as a single token whose to_i is the leading integer
    assert_equal [8005], s.send(:parse_ports, "8005-8000")
  end

  test "parse_port returns first parsed port" do
    s = build
    assert_equal 22, s.send(:parse_port, "22,80")
  end

  # ── rpc_config ──────────────────────────────────────────────────────────────

  test "rpc_config exposes msf rpc parameters" do
    cfg = build.send(:rpc_config)
    assert_equal "/api/", cfg[:uri]
    assert_equal Aegis.config.msf.rpc_host, cfg[:host]
    assert_equal Aegis.config.msf.rpc_port, cfg[:port]
    assert_equal Aegis.config.msf.rpc_ssl,  cfg[:ssl]
  end

  # ── result_to_json ─────────────────────────────────────────────────────────

  test "result_to_json serializes regular data" do
    s = build
    assert_equal "[1,2,3]", s.send(:result_to_json, [1, 2, 3])
  end

  test "result_to_json swallows JSON::GeneratorError" do
    s = build
    JSON.stub(:generate, ->(*) { raise JSON::GeneratorError.new("bad") }) do
      silence_stdout { assert_nil s.send(:result_to_json, []) }
    end
  end

  # ── log_results_to_file / cleanup_old_logs ─────────────────────────────────

  test "log_results_to_file writes a JSON file under Rails.root/logs" do
    s = build
    Dir.mktmpdir do |dir|
      Rails.stub(:root, Pathname.new(dir)) do
        silence_stdout { s.send(:log_results_to_file, '{"x":1}', 42) }
        files = Dir.glob("#{dir}/logs/scan_results_org_42_*.json")
        assert files.any?
        assert_equal '{"x":1}', File.read(files.first)
      end
    end
  end

  test "log_results_to_file rescues file errors" do
    s = build
    File.stub(:write, ->(*) { raise "disk full" }) do
      silence_stdout do
        assert_nothing_raised { s.send(:log_results_to_file, "[]", 1) }
      end
    end
  end

  test "cleanup_old_logs no-ops when log dir absent" do
    s = build
    Rails.stub(:root, Pathname.new("/tmp/aegis-no-such-dir-#{SecureRandom.hex}")) do
      silence_stdout do
        assert_nothing_raised { s.send(:cleanup_old_logs, 7) }
      end
    end
  end

  test "cleanup_old_logs deletes only files older than threshold" do
    Dir.mktmpdir do |dir|
      logs_dir = File.join(dir, "logs")
      FileUtils.mkdir_p(logs_dir)
      old_file = File.join(logs_dir, "old.json")
      new_file = File.join(logs_dir, "new.json")
      File.write(old_file, "{}")
      File.write(new_file, "{}")
      File.utime(Time.now - 30 * 86_400, Time.now - 30 * 86_400, old_file)

      Rails.stub(:root, Pathname.new(dir)) do
        silence_stdout { build.send(:cleanup_old_logs, 7) }
      end
      refute File.exist?(old_file), "old file should be deleted"
      assert File.exist?(new_file), "fresh file should remain"
    end
  end

  test "cleanup_old_logs rescues per-file delete failures" do
    Dir.mktmpdir do |dir|
      logs_dir = File.join(dir, "logs")
      FileUtils.mkdir_p(logs_dir)
      f = File.join(logs_dir, "x.json")
      File.write(f, "{}")
      File.utime(Time.now - 30 * 86_400, Time.now - 30 * 86_400, f)

      Rails.stub(:root, Pathname.new(dir)) do
        File.stub(:delete, ->(*) { raise "nope" }) do
          silence_stdout do
            assert_nothing_raised { build.send(:cleanup_old_logs, 7) }
          end
        end
      end
    end
  end

  # ── connect_network / disconnect_network ────────────────────────────────────

  test "connect_network delegates to TcpProbe" do
    s = build
    Aegis::Network::TcpProbe.stub(:alive?, ->(ip, proxy:) { [ip, proxy] }) do
      silence_stdout do
        assert_equal ["1.2.3.4", "p"], s.send(:connect_network, "1.2.3.4", "p")
      end
    end
  end

  test "disconnect_network always returns 1" do
    silence_stdout { assert_equal 1, build.send(:disconnect_network) }
  end

  # ── outbound_ip_for ─────────────────────────────────────────────────────────

  test "outbound_ip_for returns explicit lhost when configured" do
    msf = Aegis.config.msf
    overlay = Struct.new(*msf.members).new(*msf.members.map { |m| msf[m] })
    overlay.lhost = "10.99.0.1"
    config_stub = Struct.new(:msf, :scan, :nvd).new(overlay, Aegis.config.scan, Aegis.config.nvd)
    Aegis.singleton_class.alias_method(:_orig_config, :config)
    Aegis.define_singleton_method(:config) { config_stub }

    silence_stdout do
      assert_equal "10.99.0.1", build.send(:outbound_ip_for, "8.8.8.8")
    end
  ensure
    Aegis.singleton_class.send(:remove_method, :config)
    Aegis.singleton_class.alias_method(:config, :_orig_config)
    Aegis.singleton_class.send(:remove_method, :_orig_config)
  end

  test "outbound_ip_for falls back to UDPSocket-detected IP" do
    s = build
    fake_socket = Object.new
    fake_socket.define_singleton_method(:connect) { |*| }
    fake_socket.define_singleton_method(:addr) { ["AF_INET", 0, "x", "10.0.0.5"] }
    UDPSocket.singleton_class.alias_method(:_orig_open, :open)
    UDPSocket.define_singleton_method(:open) { |&blk| blk.call(fake_socket) }
    msf = Aegis.config.msf
    overlay = Struct.new(*msf.members).new(*msf.members.map { |m| msf[m] })
    overlay.lhost = nil
    config_stub = Struct.new(:msf, :scan, :nvd).new(overlay, Aegis.config.scan, Aegis.config.nvd)
    Aegis.singleton_class.alias_method(:_orig_config, :config)
    Aegis.define_singleton_method(:config) { config_stub }
    begin
      silence_stdout do
        ENV["RUNNING_IN_DOCKER"] = nil
        assert_equal "10.0.0.5", s.send(:outbound_ip_for, "8.8.8.8")
      end
    ensure
      UDPSocket.singleton_class.send(:remove_method, :open)
      UDPSocket.singleton_class.alias_method(:open, :_orig_open)
      UDPSocket.singleton_class.send(:remove_method, :_orig_open)
      Aegis.singleton_class.remove_method(:config)
      Aegis.singleton_class.alias_method(:config, :_orig_config)
      Aegis.singleton_class.remove_method(:_orig_config)
    end
  end

  # ── rpc_client ──────────────────────────────────────────────────────────────

  test "rpc_client returns nil when MSF_RPC_PASS unset" do
    msf = Aegis.config.msf
    overlay = Struct.new(*msf.members).new(*msf.members.map { |m| msf[m] })
    overlay.rpc_pass = nil
    config_stub = Struct.new(:msf, :scan, :nvd).new(overlay, Aegis.config.scan, Aegis.config.nvd)
    Aegis.singleton_class.alias_method(:_orig_config, :config)
    Aegis.define_singleton_method(:config) { config_stub }

    silence_stdout do
      Thread.current[:msf_rpc] = nil
      Thread.current[:msf_rpc_unavailable] = nil
      assert_nil build.send(:rpc_client)
    end
  ensure
    Aegis.singleton_class.send(:remove_method, :config)
    Aegis.singleton_class.alias_method(:config, :_orig_config)
    Aegis.singleton_class.send(:remove_method, :_orig_config)
    Thread.current[:msf_rpc_unavailable] = nil
  end

  test "rpc_client returns cached client from Thread.current" do
    sentinel = Object.new
    Thread.current[:msf_rpc] = sentinel
    assert_equal sentinel, build.send(:rpc_client)
  ensure
    Thread.current[:msf_rpc] = nil
    Thread.current[:msf_rpc_unavailable] = nil
  end

  # ── attack ──────────────────────────────────────────────────────────────────

  test "attack falls through to subprocess when rpc_client is nil" do
    s = build
    s.stub(:rpc_client, nil) do
      s.stub(:attack_subprocess, ->(*) { :sub_called }) do
        silence_stdout do
          assert_equal :sub_called, s.send(:attack, { "metasploit_module" => "x" }, "1.1.1.1", 80, nil)
        end
      end
    end
  end

  test "attack delegates to rpc_run_auxiliary in safe mode" do
    s = build(options: { safe_mode: true })
    s.stub(:rpc_client, Object.new) do
      s.stub(:rpc_run_auxiliary, ->(*) { :aux }) do
        silence_stdout do
          assert_equal :aux, s.send(:attack, { "metasploit_module" => "auxiliary/x" }, "1.1.1.1", 22, nil)
        end
      end
    end
  end

  test "attack delegates to rpc_run_exploit in vuln mode" do
    s = build
    s.stub(:rpc_client, Object.new) do
      s.stub(:rpc_run_exploit, ->(*) { :exp }) do
        silence_stdout do
          assert_equal :exp, s.send(:attack, { "metasploit_module" => "exploit/x" }, "1.1.1.1", 22, nil)
        end
      end
    end
  end

  test "attack rescues exceptions and returns failure tuple" do
    s = build
    s.stub(:rpc_client, ->(*) { raise "boom" }) do
      silence_stdout do
        result = s.send(:attack, { "metasploit_module" => "x" }, "1.1.1.1", 80, nil)
        assert_equal({ success: false, evidence: nil }, result)
      end
    end
  end

  # ── DB helpers ──────────────────────────────────────────────────────────────

  test "create_scan_target returns nil when scan is missing" do
    silence_stdout do
      assert_nil build.send(:create_scan_target, assets(:asset_one).id)
    end
  end

  test "create_scan_target returns nil when asset_id is missing" do
    silence_stdout do
      assert_nil build(scan: scans(:running_scan)).send(:create_scan_target, nil)
    end
  end

  test "create_scan_target inserts and returns id" do
    s = build(scan: scans(:running_scan))
    silence_stdout do
      id = s.send(:create_scan_target, assets(:asset_one).id)
      assert id
    end
  end

  test "complete_scan_target no-ops when id is nil" do
    silence_stdout do
      assert_nothing_raised { build.send(:complete_scan_target, nil, 1, 1) }
    end
  end

  test "complete_scan_target updates row" do
    s = build(scan: scans(:running_scan))
    silence_stdout do
      id = s.send(:create_scan_target, assets(:asset_one).id)
      assert_nothing_raised { s.send(:complete_scan_target, id, 5, 2) }
    end
  end

  test "create_scan_exploit no-ops when scan or asset/exploit missing" do
    silence_stdout do
      assert_nothing_raised { build.send(:create_scan_exploit, nil, nil, "success", 1) }
    end
  end

  test "create_scan_exploit normalizes unknown result to 'failed'" do
    s = build(scan: scans(:running_scan))
    silence_stdout do
      assert_nothing_raised do
        s.send(:create_scan_exploit, assets(:asset_one).id, exploits(:exploit_one).id, "weird", 100)
      end
    end
  end

  test "create_finding inserts a finding row" do
    s = build(scan: scans(:running_scan))
    silence_stdout do
      assert_difference "Finding.count", 1 do
        s.send(:create_finding, assets(:asset_one).id, exploits(:exploit_one).id,
               "critical", "evidence", 445)
      end
    end
  end

  test "create_finding accepts nil port and bad severity" do
    s = build(scan: scans(:running_scan))
    silence_stdout do
      assert_difference "Finding.count", 1 do
        s.send(:create_finding, assets(:asset_one).id, exploits(:exploit_one).id,
               nil, "evidence", nil)
      end
    end
  end

  test "create_finding no-ops without scan" do
    silence_stdout do
      assert_no_difference "Finding.count" do
        build.send(:create_finding, assets(:asset_one).id, exploits(:exploit_one).id,
                   "high", "ev", 22)
      end
    end
  end

  # ── get_targets ─────────────────────────────────────────────────────────────

  test "get_targets returns parsed asset rows for org" do
    s = build(asset_ids: [assets(:asset_one).id])
    silence_stdout do
      targets = s.send(:get_targets, organizations(:acme).id)
      assert targets.any? { |t| t["asset_id"] == assets(:asset_one).id }
    end
  end

  test "get_targets resolves agent proxy when use_agent enabled" do
    s = build(options: { use_agent: true }, asset_ids: [assets(:asset_one).id])
    fake_agent = Object.new
    fake_agent.define_singleton_method(:tunnel_port) { 9100 }
    Agent.stub(:find_for_target, ->(*) { fake_agent }) do
      silence_stdout do
        targets = s.send(:get_targets, organizations(:acme).id)
        assert targets.first["proxy"]&.include?("9100")
      end
    end
  end

  test "get_targets rescues query errors and returns []" do
    s = build
    ActiveRecord::Base.connection.stub(:select_all, ->(*) { raise "db gone" }) do
      silence_stdout do
        assert_equal [], s.send(:get_targets, 1)
      end
    end
  end

  # ── module enumeration & metadata ──────────────────────────────────────────

  test "platform_dirs / auxiliary_scanner_dirs delegate to PlatformDirs" do
    s = build
    assert_equal Aegis::Msf::PlatformDirs.for_exploits("linux"), s.send(:platform_dirs, "linux")
    assert_equal Aegis::Msf::PlatformDirs.for_auxiliary_scanners("linux"),
                 s.send(:auxiliary_scanner_dirs, "linux")
  end

  test "read_module_rank delegates to MsfModuleParser" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, "Rank = ExcellentRanking\n")
      assert_equal "critical", build.send(:read_module_rank, path)
    end
  end

  test "parse_module_metadata returns fields from metadata_full" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, "'Name' => 'Mod', 'References' => [['CVE','2026-1']]")
      meta = build.send(:parse_module_metadata, path)
      assert_equal "Mod", meta[:name]
      assert_equal "CVE-2026-1", meta[:cve_id]
    end
  end

  test "get_modules_for_target enumerates files under MSF_BASE in vuln mode" do
    s = build(filter: { "module_allowlist" => nil })
    Dir.stub(:glob, ["#{ScanService::MSF_BASE}/windows/smb/eternalblue.rb"]) do
      silence_stdout do
        mods = s.send(:get_modules_for_target, "windows")
        assert_equal 1, mods.size
        assert_match(%r{exploit/}, mods.first[:path])
      end
    end
  end

  test "get_modules_for_target uses auxiliary base in safe mode" do
    s = build(options: { safe_mode: true })
    Dir.stub(:glob, ["#{ScanService::MSF_AUXILIARY_BASE}/scanner/smb/probe.rb"]) do
      silence_stdout do
        mods = s.send(:get_modules_for_target, "windows")
        assert mods.first[:path].start_with?("auxiliary/")
      end
    end
  end

  test "get_modules_for_target falls back to full tree if subdirs are empty" do
    s = build
    counts = { calls: 0 }
    glob_stub = ->(pattern) {
      counts[:calls] += 1
      pattern.include?("**") && !pattern.include?("/linux/") &&
        !pattern.include?("/unix/") && !pattern.include?("/multi/") ?
        ["#{ScanService::MSF_BASE}/something/x.rb"] : []
    }
    Dir.stub(:glob, glob_stub) do
      silence_stdout do
        mods = s.send(:get_modules_for_target, "linux")
        assert_equal 1, mods.size
      end
    end
  end

  test "get_modules_for_target applies allowlist filter" do
    s = build(filter: { "module_allowlist" => ["exploit/windows/smb/eternalblue"] })
    Dir.stub(:glob, [
      "#{ScanService::MSF_BASE}/windows/smb/eternalblue.rb",
      "#{ScanService::MSF_BASE}/windows/smb/other.rb"
    ]) do
      silence_stdout do
        mods = s.send(:get_modules_for_target, "windows")
        assert_equal ["exploit/windows/smb/eternalblue"], mods.map { |m| m[:path] }
      end
    end
  end

  # ── get_or_create_exploit_record ───────────────────────────────────────────

  test "get_or_create_exploit_record creates a new Exploit record" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "fresh.rb")
      File.write(path, "Rank = GoodRanking\n'Name' => 'Fresh Mod'")
      module_path = "exploit/test/fresh_#{SecureRandom.hex(4)}"
      assert_difference "Exploit.count", 1 do
        rec = build.send(:get_or_create_exploit_record, module_path, path)
        assert_equal module_path, rec.metasploit_module
        assert_equal "high", rec.severity
      end
    end
  end

  test "get_or_create_exploit_record reuses existing Exploit by exploit_id" do
    existing = exploits(:exploit_one)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "exists.rb")
      File.write(path, "Rank = ExcellentRanking\n")
      assert_no_difference "Exploit.count" do
        rec = build.send(:get_or_create_exploit_record, existing.exploit_id, path)
        assert_equal existing.id, rec.id
      end
    end
  end

  test "get_or_create_exploit_record falls back via find_by! on RecordNotUnique" do
    existing = exploits(:exploit_two)
    Dir.mktmpdir do |dir|
      path = File.join(dir, "race.rb")
      File.write(path, "Rank = NormalRanking\n")
      Exploit.stub(:find_or_initialize_by, ->(*) {
        e = Exploit.new(exploit_id: "exploit/test/race_#{SecureRandom.hex(4)}")
        e.define_singleton_method(:save!) { raise ActiveRecord::RecordNotUnique.new("dup") }
        e.define_singleton_method(:new_record?) { true }
        e.define_singleton_method(:description) { nil }
        e
      }) do
        Exploit.stub(:find_by!, ->(*) { existing }) do
          rec = build.send(:get_or_create_exploit_record, "exploit/test/race", path)
          assert_equal existing.id, rec.id
        end
      end
    end
  end

  # ── detect_lhost_via_msfrpc ────────────────────────────────────────────────

  test "detect_lhost_via_msfrpc returns nil when no rpc client" do
    s = build
    s.stub(:rpc_client, nil) do
      silence_stdout { assert_nil s.send(:detect_lhost_via_msfrpc, "1.2.3.4") }
    end
  end

  test "detect_lhost_via_msfrpc parses outbound IP from console output" do
    s = build
    s.define_singleton_method(:sleep) { |*| nil }
    fake_client = Object.new
    def fake_client.msfrpc_call(*args)
      case args.first
      when "console.create"  then { "id" => "C1" }
      when "console.read"    then { "data" => "127.0.0.1\n10.0.5.7\n" }
      else nil
      end
    end
    fake_client.define_singleton_method(:call) { |*a| fake_client.msfrpc_call(*a) }
    # minitest's .stub(method, callable) invokes the callable if it responds_to?(:call) —
    # so we wrap fake_client in a lambda that returns it
    s.stub(:rpc_client, ->(*) { fake_client }) do
      silence_stdout do
        assert_equal "10.0.5.7", s.send(:detect_lhost_via_msfrpc, "8.8.8.8")
      end
    end
  end

  test "detect_lhost_via_msfrpc rescues errors raised after console.create" do
    s = build
    s.define_singleton_method(:sleep) { |*| nil }
    fake_client = Object.new
    fake_client.define_singleton_method(:call) do |method, *_a|
      method == "console.create" ? { "id" => "C1" } : raise("rpc went away")
    end
    s.stub(:rpc_client, ->(*) { fake_client }) do
      silence_stdout { assert_nil s.send(:detect_lhost_via_msfrpc, "1.1.1.1") }
    end
  end

  # ── select_payload ──────────────────────────────────────────────────────────

  def fake_payload_client(payloads)
    obj = Object.new
    obj.define_singleton_method(:call) { |_method, *_a| { "payloads" => payloads } }
    obj
  end

  test "select_payload returns nil when no compatible payloads" do
    silence_stdout do
      assert_nil build.send(:select_payload, fake_payload_client([]), "x", false)
    end
  end

  test "select_payload picks preferred reverse payload when available" do
    payloads = %w[some/other cmd/unix/reverse_netcat fancy/junk]
    assert_equal "cmd/unix/reverse_netcat",
                 build.send(:select_payload, fake_payload_client(payloads), "x", false)
  end

  test "select_payload falls back to any reverse payload" do
    payloads = %w[some/random/reverse_xyz]
    assert_equal "some/random/reverse_xyz",
                 build.send(:select_payload, fake_payload_client(payloads), "x", false)
  end

  test "select_payload picks preferred bind payload when use_bind is true" do
    payloads = %w[cmd/unix/bind_perl other]
    assert_equal "cmd/unix/bind_perl",
                 build.send(:select_payload, fake_payload_client(payloads), "x", true)
  end

  test "select_payload falls back to first payload when no preferences match" do
    payloads = %w[totally/random/thing]
    assert_equal "totally/random/thing",
                 build.send(:select_payload, fake_payload_client(payloads), "x", true)
  end

  test "select_payload rescues client failures and returns nil" do
    bad = Object.new
    bad.define_singleton_method(:call) { |*| raise "rpc dead" }
    silence_stdout do
      assert_nil build.send(:select_payload, bad, "x", false)
    end
  end

  # ── resource-file builders ──────────────────────────────────────────────────

  test "build_exploit_rc emits use/set/run lines" do
    s = build
    s.stub(:outbound_ip_for, "10.0.0.5") do
      rc = s.send(:build_exploit_rc,
                  { "metasploit_module" => "exploit/x/y", "default_payload" => "cmd/foo" },
                  "1.2.3.4", 8080, "socks5://10.0.0.1:1080")
      assert_match %r{^use exploit/x/y$}, rc
      assert_match %r{^set RHOSTS 1\.2\.3\.4$}, rc
      assert_match %r{^set RPORT 8080$}, rc
      assert_match %r{^set PAYLOAD cmd/foo$}, rc
      assert_match %r{^set LHOST 10\.0\.0\.5$}, rc
      assert_match %r{^set Proxies socks5://10\.0\.0\.1:1080$}, rc
      assert_match %r{^run -z$}, rc
      refute_match %r{sessions -l}, rc
      assert rc.end_with?("\n")
    end
  end

  test "build_exploit_rc omits port/payload/proxy when not provided" do
    s = build
    s.stub(:outbound_ip_for, "127.0.0.1") do
      rc = s.send(:build_exploit_rc, { "metasploit_module" => "exploit/x" }, "1.1.1.1", nil, nil)
      refute_match %r{set RPORT}, rc
      refute_match %r{set PAYLOAD}, rc
      refute_match %r{set Proxies}, rc
      refute_match %r{sessions -l}, rc
    end
  end

  test "build_auxiliary_rc emits expected commands" do
    rc = build.send(:build_auxiliary_rc,
                    { "metasploit_module" => "auxiliary/scanner/smb/probe" },
                    "1.1.1.1", 445, "socks5://10.0.0.1:1080")
    assert_match %r{^use auxiliary/scanner/smb/probe$}, rc
    assert_match %r{^set RHOSTS 1\.1\.1\.1$}, rc
    assert_match %r{^set RPORT 445$}, rc
    assert_match %r{^set Proxies socks5://10\.0\.0\.1:1080$}, rc
    assert_match %r{^run$}, rc
  end

  test "build_resource_file dispatches to safe-mode auxiliary builder" do
    s = build(options: { safe_mode: true })
    rc = s.send(:build_resource_file,
                { "metasploit_module" => "auxiliary/x" }, "1.1.1.1", nil, nil)
    assert_match %r{^use auxiliary/x$}, rc
  end

  test "build_resource_file dispatches to exploit builder by default" do
    s = build
    s.stub(:outbound_ip_for, "127.0.0.1") do
      rc = s.send(:build_resource_file,
                  { "metasploit_module" => "exploit/x" }, "1.1.1.1", nil, nil)
      assert_match %r{^use exploit/x$}, rc
    end
  end

  # ── with_clean_bundler_env ──────────────────────────────────────────────────

  test "with_clean_bundler_env yields and restores under Bundler" do
    captured = nil
    if defined?(Bundler)
      Bundler.stub(:with_unbundled_env, ->(&blk) { captured = :inside; blk.call }) do
        build.send(:with_clean_bundler_env) { captured = :inside }
      end
    end
    assert_equal :inside, captured if defined?(Bundler)
  end

  test "with_clean_bundler_env clears and restores env when Bundler is hidden" do
    saved_bundler = Object.send(:remove_const, :Bundler) if defined?(Bundler)
    s = build
    ENV["RUBYLIB"] = "/test/path"
    captured_inner = nil
    s.send(:with_clean_bundler_env) do
      captured_inner = ENV["RUBYLIB"]
    end
    assert_nil captured_inner, "expected RUBYLIB cleared inside the block"
    assert_equal "/test/path", ENV["RUBYLIB"]
  ensure
    ENV.delete("RUBYLIB")
    Object.const_set(:Bundler, saved_bundler) if saved_bundler
  end

  # ── dump_msf_debug ──────────────────────────────────────────────────────────

  test "dump_msf_debug writes a debug log file" do
    Dir.mktmpdir do |dir|
      Rails.stub(:root, Pathname.new(dir)) do
        silence_stdout do
          build.send(:dump_msf_debug,
                     { "metasploit_module" => "exploit/test/foo", "name" => "Test" },
                     "1.1.1.1", 80, nil, "raw", "clean", true, [])
        end
        files = Dir.glob("#{dir}/logs/msf_debug/*.log")
        assert files.any?
        contents = File.read(files.first)
        assert_match(/AEGIS MSF DEBUG DUMP/, contents)
        assert_match(/exploit\/test\/foo/, contents)
      end
    end
  end

  test "dump_msf_debug embeds rc file contents when path provided" do
    Dir.mktmpdir do |dir|
      Rails.stub(:root, Pathname.new(dir)) do
        rc = File.join(dir, "x.rc")
        File.write(rc, "use foo\nrun\n")
        silence_stdout do
          build.send(:dump_msf_debug,
                     { "metasploit_module" => "x" }, "1.1.1.1", 22, rc,
                     "raw", "clean", false, [])
        end
        contents = File.read(Dir.glob("#{dir}/logs/msf_debug/*.log").first)
        assert_match(/use foo/, contents)
      end
    end
  end

  test "dump_msf_debug rescues file write errors" do
    File.stub(:write, ->(*) { raise "disk full" }) do
      silence_stdout do
        assert_nothing_raised do
          build.send(:dump_msf_debug,
                     { "metasploit_module" => "x" }, "1.1.1.1", 80, nil,
                     "", "", true, [])
        end
      end
    end
  end

  # ── rpc_run_exploit ─────────────────────────────────────────────────────────

  test "rpc_run_exploit returns success when new session opens" do
    s = build
    s.define_singleton_method(:sleep) { |*| nil }
    session_calls = 0
    handlers = {
      "module.compatible_payloads" => -> { { "payloads" => ["cmd/unix/reverse_netcat"] } },
      "module.execute"             => ->(*) { { "job_id" => 42 } },
      "session.list"               => -> {
        session_calls += 1
        session_calls > 1 ? { "7" => { "tunnel_local" => "192.168.56.1:4444", "tunnel_peer" => "192.168.56.102:54321", "type" => "shell" } } : {}
      },
      "session.shell_write" => -> { nil },
      "session.shell_read"  => -> { { "data" => "uid=0(root) gid=0(root)\n" } },
      "session.stop"        => -> { nil },
      "job.stop"            => -> { nil }
    }
    client = Object.new
    client.define_singleton_method(:call) { |method, *_a| handlers[method]&.call }
    silence_stdout do
      result = s.send(:rpc_run_exploit, client,
                      { "metasploit_module" => "exploit/x", "default_payload" => nil },
                      "192.168.56.102", 21, nil, 30)
      assert result[:success]
      assert_match(/192\.168\.56\.102/, result[:evidence])
      assert_match(/uid=0\(root\)/, result[:evidence])
    end
  end

  test "rpc_run_exploit returns failure when no payload selected" do
    s = build
    handlers = {
      "module.compatible_payloads" => -> { { "payloads" => [] } }
    }
    client = Object.new
    client.define_singleton_method(:call) { |method, *_a| handlers[method]&.call }
    silence_stdout do
      result = s.send(:rpc_run_exploit, client,
                      { "metasploit_module" => "exploit/x", "default_payload" => nil },
                      "1.1.1.1", 80, nil, 5)
      refute result[:success]
      assert_nil result[:evidence]
    end
  end

  test "rpc_run_exploit returns failure when no session opens within timeout" do
    s = build
    s.define_singleton_method(:sleep) { |*| nil }
    handlers = {
      "module.execute" => ->(*) { { "job_id" => 1 } },
      "session.list"   => -> { {} },
      "job.stop"       => -> { nil }
    }
    client = Object.new
    client.define_singleton_method(:call) { |method, *_a| handlers[method]&.call }
    silence_stdout do
      # timeout_secs = 0 so the polling loop never runs
      result = s.send(:rpc_run_exploit, client,
                      { "metasploit_module" => "exploit/x", "default_payload" => "cmd/foo" },
                      "1.1.1.1", 80, nil, 0)
      refute result[:success]
    end
  end

  test "rpc_run_exploit calls module.execute with RHOSTS PAYLOAD and detected LHOST" do
    s = build
    s.define_singleton_method(:sleep) { |*| nil }
    s.stub(:outbound_ip_for, "192.168.56.1") do
      captured_opts = nil
      handlers = {
        "module.execute" => ->(*a) { captured_opts = a[2]; { "job_id" => 1 } },
        "session.list"   => -> { {} },
        "job.stop"       => -> { nil }
      }
      client = Object.new
      client.define_singleton_method(:call) { |method, *a| handlers[method]&.call(*a) }
      silence_stdout do
        s.send(:rpc_run_exploit, client,
               { "metasploit_module" => "exploit/x", "default_payload" => "cmd/unix/reverse_netcat" },
               "192.168.56.102", 21, nil, 0)
      end
      assert_equal "192.168.56.102", captured_opts["RHOSTS"]
      assert_equal "cmd/unix/reverse_netcat", captured_opts["PAYLOAD"]
      assert_equal "192.168.56.1", captured_opts["LHOST"]
    end
  end

  test "rpc_run_exploit rescues Msf::RPC::ServerException and returns failure" do
    s = build
    client = Object.new
    client.define_singleton_method(:call) { |*| raise Msf::RPC::ServerException.new(nil, nil, nil) }
    silence_stdout do
      result = s.send(:rpc_run_exploit, client,
                      { "metasploit_module" => "exploit/x", "default_payload" => "cmd/foo" },
                      "1.1.1.1", 80, nil, 5)
      refute result[:success]
    end
  end

  # ── rpc_run_auxiliary ───────────────────────────────────────────────────────

  test "rpc_run_auxiliary detects success from completion line" do
    s = build(options: { safe_mode: true })
    s.define_singleton_method(:sleep) { |*| nil }
    Thread.current[:msf_aux_console] = nil
    success_payload = { "data" => "[+] 1.1.1.1:445 - Vulnerable to MS17-010\nAuxiliary module execution completed\n", "busy" => false }
    drain_count = 0
    handlers = {
      "console.create"  => -> { { "id" => "C9" } },
      "console.write"   => -> { nil },
      "console.read"    => -> {
        # Two reads up-front are the "drain" that the method does before sending
        # commands; only after those should the success payload be returned.
        drain_count += 1
        drain_count <= 2 ? { "data" => "", "busy" => false } : success_payload
      },
      "console.destroy" => -> { nil }
    }
    client = Object.new
    client.define_singleton_method(:call) { |method, *_a| handlers[method]&.call }
    silence_stdout do
      result = s.send(:rpc_run_auxiliary, client,
                      { "metasploit_module" => "auxiliary/scanner/smb/probe" },
                      "1.1.1.1", 445, nil, 10)
      assert result[:success]
    end
  end

  test "rpc_run_auxiliary uses shared console when one is open on the thread" do
    s = build(options: { safe_mode: true })
    Thread.current[:msf_aux_console] = "SHARED1"
    s.define_singleton_method(:sleep) { |*| nil }
    output_seq = [{ "data" => "Auxiliary module execution completed\n", "busy" => false }]
    saw = []
    handlers = {
      "console.create"  => -> { saw << :create; { "id" => "X" } },
      "console.write"   => -> { saw << :write; nil },
      "console.read"    => -> { saw << :read; output_seq.shift || { "data" => "", "busy" => false } },
      "console.destroy" => -> { saw << :destroy; nil }
    }
    client = Object.new
    client.define_singleton_method(:call) { |method, *_a| handlers[method]&.call }
    silence_stdout do
      s.send(:rpc_run_auxiliary, client, { "metasploit_module" => "auxiliary/x" }, "1.1.1.1", 445, nil, 10)
    end
    refute_includes saw, :create
    refute_includes saw, :destroy
  ensure
    Thread.current[:msf_aux_console] = nil
  end

  test "rpc_run_auxiliary rescues Msf::RPC::ServerException" do
    s = build(options: { safe_mode: true })
    Thread.current[:msf_aux_console] = "SHARED2"
    client = Object.new
    client.define_singleton_method(:call) { |*| raise Msf::RPC::ServerException.new(nil, nil, nil) }
    silence_stdout do
      result = s.send(:rpc_run_auxiliary, client,
                      { "metasploit_module" => "auxiliary/x" }, "1.1.1.1", 445, nil, 5)
      refute result[:success]
      assert_nil Thread.current[:msf_aux_console]
    end
  end

  # ── attack_subprocess ───────────────────────────────────────────────────────

  test "attack_subprocess parses success from stubbed PTY output" do
    s = build
    fake_master = StringIO.new("[*] Meterpreter session 1 opened (1.1.1.1)\n")
    fake_master.define_singleton_method(:readpartial) do |n|
      data = read(n)
      raise EOFError if data.nil? || data.empty?
      data
    end
    fake_master.define_singleton_method(:close) { }
    fake_slave = Object.new
    fake_slave.define_singleton_method(:close) { }

    s.stub(:with_clean_bundler_env, ->(&blk) { blk.call }) do
      PTY.stub(:spawn, [fake_master, fake_slave, 1234]) do
        Process.stub(:wait, nil) do
          silence_stdout do
            result = s.send(:attack_subprocess,
                            { "metasploit_module" => "exploit/x", "name" => "Test", "default_payload" => nil },
                            "1.1.1.1", 80, nil, 1)
            assert result[:success]
          end
        end
      end
    end
  end

  test "attack_subprocess rescues outer errors and returns failure tuple" do
    s = build
    s.stub(:with_clean_bundler_env, ->(&blk) { blk.call }) do
      PTY.stub(:spawn, ->(*) { raise "no pty" }) do
        silence_stdout do
          result = s.send(:attack_subprocess,
                          { "metasploit_module" => "exploit/x", "name" => "T" },
                          "1.1.1.1", 80, nil, 1)
          refute result[:success]
        end
      end
    end
  end

  # ── perform end-to-end with stubs ──────────────────────────────────────────

  test "perform orchestrates a successful scan via stubs" do
    scan = scans(:running_scan)
    asset_id = assets(:asset_one).id
    exploit  = exploits(:exploit_one)
    s = build(scan: scan, asset_ids: [asset_id])

    s.define_singleton_method(:get_targets) do |_org_id|
      [{ "ip" => "1.1.1.1", "asset_id" => asset_id, "ports" => [80], "proxy" => nil, "os" => "linux" }]
    end
    s.define_singleton_method(:connect_network)        { |*| 1 }
    s.define_singleton_method(:get_modules_for_target) { |*| [{ path: "exploit/x", file: "/tmp/x.rb" }] }
    s.define_singleton_method(:read_module_rank)       { |*| "high" }
    s.define_singleton_method(:get_or_create_exploit_record) { |*| exploit }
    s.define_singleton_method(:attack) { |*| { success: true, evidence: "OK" } }

    silence_stdout do
      assert_nothing_raised { s.send(:perform) }
    end
    scan.reload
    assert_equal "completed", scan.status
    assert scan.findings_count >= 1
  end

  test "perform marks scan failed and re-raises on inner error" do
    scan = scans(:running_scan)
    s = build(scan: scan)
    s.define_singleton_method(:get_targets) { |_| raise "boom" }

    silence_stdout do
      assert_raises(RuntimeError) { s.send(:perform) }
    end
    scan.reload
    assert_equal "failed", scan.status
  end

  test "perform skips target when connect_network returns 0" do
    scan = scans(:running_scan)
    asset_id = assets(:asset_one).id
    s = build(scan: scan, asset_ids: [asset_id])

    s.define_singleton_method(:get_targets) do |_org_id|
      [{ "ip" => "1.1.1.1", "asset_id" => asset_id, "ports" => [22], "proxy" => nil, "os" => "linux" }]
    end
    s.define_singleton_method(:connect_network) { |*| 0 }
    silence_stdout do
      assert_nothing_raised { s.send(:perform) }
    end
    scan.reload
    assert_equal "completed", scan.status
    assert_equal 0, scan.findings_count
  end

  # ── perform extended branches ──────────────────────────────────────────────

  test "perform opens shared console in safe mode and respects port_override" do
    scan = scans(:running_scan)
    asset_id = assets(:asset_one).id
    exploit  = exploits(:exploit_one)
    s = build(scan: scan, asset_ids: [asset_id],
              options: { safe_mode: true, port_override: "8000-8005" })

    fake_aux = Object.new
    fake_aux.define_singleton_method(:call) do |method, *_a|
      method == "console.create" ? { "id" => "AUX1" } : nil
    end

    s.define_singleton_method(:get_targets) do |_org_id|
      [{ "ip" => "1.1.1.1", "asset_id" => asset_id, "ports" => [80], "proxy" => nil, "os" => "linux" }]
    end
    s.define_singleton_method(:rpc_client) { fake_aux }
    s.define_singleton_method(:connect_network) { |*| 1 }
    s.define_singleton_method(:get_modules_for_target) { |*| [{ path: "auxiliary/x", file: "/tmp/x.rb" }] }
    s.define_singleton_method(:read_module_rank) { |*| "high" }
    s.define_singleton_method(:get_or_create_exploit_record) { |*| exploit }
    s.define_singleton_method(:attack) { |*| { success: false, evidence: nil } }

    silence_stdout do
      assert_nothing_raised { s.send(:perform) }
    end
    scan.reload
    assert_equal "completed", scan.status
    assert_nil Thread.current[:msf_aux_console]
  end

  test "perform opens and closes shared exploit console in exploit mode" do
    scan = scans(:running_scan)
    asset_id = assets(:asset_one).id
    exploit  = exploits(:exploit_one)
    s = build(scan: scan, asset_ids: [asset_id], options: {})

    fake_exploit_client = Object.new
    fake_exploit_client.define_singleton_method(:call) do |method, *_a|
      method == "console.create" ? { "id" => "EXP1" } : nil
    end

    s.define_singleton_method(:get_targets) do |_org_id|
      [{ "ip" => "1.1.1.1", "asset_id" => asset_id, "ports" => [80], "proxy" => nil, "os" => "linux" }]
    end
    s.define_singleton_method(:rpc_client) { fake_exploit_client }
    s.define_singleton_method(:connect_network) { |*| 1 }
    s.define_singleton_method(:get_modules_for_target) { |*| [{ path: "exploit/x", file: "/tmp/x.rb" }] }
    s.define_singleton_method(:read_module_rank) { |*| "high" }
    s.define_singleton_method(:get_or_create_exploit_record) { |*| exploit }
    s.define_singleton_method(:attack) { |*| { success: false, evidence: nil } }

    silence_stdout do
      assert_nothing_raised { s.send(:perform) }
    end
    scan.reload
    assert_equal "completed", scan.status
    assert_nil Thread.current[:msf_exploit_console]
  end

  test "perform records exploit_code and isVulnerable when use_agent enabled" do
    scan = scans(:running_scan)
    asset_id = assets(:asset_one).id
    exploit  = exploits(:exploit_one)
    s = build(scan: scan, asset_ids: [asset_id], options: { use_agent: true })

    Dir.mktmpdir do |dir|
      module_file = File.join(dir, "x.rb")
      File.write(module_file, "MODULE SOURCE")

      s.define_singleton_method(:get_targets) do |_org_id|
        [{ "ip" => "1.1.1.1", "asset_id" => asset_id, "ports" => [80], "proxy" => nil, "os" => "linux" }]
      end
      s.define_singleton_method(:connect_network) { |*| 1 }
      s.define_singleton_method(:get_modules_for_target) { |*| [{ path: "exploit/x", file: module_file }] }
      s.define_singleton_method(:read_module_rank) { |*| "high" }
      s.define_singleton_method(:get_or_create_exploit_record) { |*| exploit }
      s.define_singleton_method(:attack) { |*| { success: true, evidence: "OK" } }

      silence_stdout do
        s.send(:perform)
      end
      report = Report.where(scan_id: scan.id).order(:id).last
      assert_equal "whitebox", report.report_type
      finding = Array(report.report_data).first
      assert_equal true, finding["isVulnerable"]
      assert_equal "MODULE SOURCE", finding["exploit_code"]
    end
  end

  test "perform recovers when an inner thread raises (rescues per-target)" do
    scan = scans(:running_scan)
    asset_id = assets(:asset_one).id
    s = build(scan: scan, asset_ids: [asset_id])

    s.define_singleton_method(:get_targets) do |_org_id|
      [{ "ip" => "1.1.1.1", "asset_id" => asset_id, "ports" => [80], "proxy" => nil, "os" => "linux" }]
    end
    s.define_singleton_method(:connect_network) { |*| raise "no route" }

    silence_stdout do
      assert_nothing_raised { s.send(:perform) }
    end
    scan.reload
    assert_equal "completed", scan.status
  end

  # ── outbound_ip_for Docker fallback ────────────────────────────────────────

  test "outbound_ip_for falls back via msfrpcd when running in Docker with private IP" do
    s = build
    fake_socket = Object.new
    fake_socket.define_singleton_method(:connect) { |*| }
    fake_socket.define_singleton_method(:addr) { ["AF_INET", 0, "x", "172.17.0.5"] }
    UDPSocket.singleton_class.alias_method(:_orig_open, :open)
    UDPSocket.define_singleton_method(:open) { |&blk| blk.call(fake_socket) }
    ENV["RUNNING_IN_DOCKER"] = "1"
    s.define_singleton_method(:detect_lhost_via_msfrpc) { |_, **| "10.99.0.1" }
    msf = Aegis.config.msf
    overlay = Struct.new(*msf.members).new(*msf.members.map { |m| msf[m] })
    overlay.lhost = nil
    config_stub = Struct.new(:msf, :scan, :nvd).new(overlay, Aegis.config.scan, Aegis.config.nvd)
    Aegis.singleton_class.alias_method(:_orig_config, :config)
    Aegis.define_singleton_method(:config) { config_stub }

    silence_stdout do
      assert_equal "10.99.0.1", s.send(:outbound_ip_for, "8.8.8.8")
    end
  ensure
    UDPSocket.singleton_class.send(:remove_method, :open)
    UDPSocket.singleton_class.alias_method(:open, :_orig_open)
    UDPSocket.singleton_class.send(:remove_method, :_orig_open)
    ENV.delete("RUNNING_IN_DOCKER")
    Aegis.singleton_class.remove_method(:config) rescue nil
    Aegis.singleton_class.alias_method(:config, :_orig_config) rescue nil
    Aegis.singleton_class.remove_method(:_orig_config) rescue nil
  end

  # ── rpc_client error/login paths ───────────────────────────────────────────

  test "rpc_client logs in and caches the client on success" do
    Thread.current[:msf_rpc] = nil
    Thread.current[:msf_rpc_unavailable] = nil
    msf = Aegis.config.msf
    overlay = Struct.new(*msf.members).new(*msf.members.map { |m| msf[m] })
    overlay.rpc_pass = "topsecret"
    config_stub = Struct.new(:msf, :scan, :nvd).new(overlay, Aegis.config.scan, Aegis.config.nvd)
    Aegis.singleton_class.alias_method(:_orig_config, :config)
    Aegis.define_singleton_method(:config) { config_stub }

    fake_client = Object.new
    fake_client.define_singleton_method(:login) { |*| true }
    Msf::RPC::Client.stub(:new, fake_client) do
      Timeout.stub(:timeout, ->(_n, &blk) { blk.call }) do
        silence_stdout do
          assert_equal fake_client, build.send(:rpc_client)
          assert_equal fake_client, Thread.current[:msf_rpc]
        end
      end
    end
  ensure
    Aegis.singleton_class.send(:remove_method, :config)
    Aegis.singleton_class.alias_method(:config, :_orig_config)
    Aegis.singleton_class.send(:remove_method, :_orig_config)
    Thread.current[:msf_rpc] = nil
    Thread.current[:msf_rpc_unavailable] = nil
  end

  test "rpc_client returns nil when login times out" do
    Thread.current[:msf_rpc] = nil
    Thread.current[:msf_rpc_unavailable] = nil
    msf = Aegis.config.msf
    overlay = Struct.new(*msf.members).new(*msf.members.map { |m| msf[m] })
    overlay.rpc_pass = "whatever"
    config_stub = Struct.new(:msf, :scan, :nvd).new(overlay, Aegis.config.scan, Aegis.config.nvd)
    Aegis.singleton_class.alias_method(:_orig_config, :config)
    Aegis.define_singleton_method(:config) { config_stub }

    fake_client = Object.new
    fake_client.define_singleton_method(:login) { |*| raise "rpc login failed" }
    Msf::RPC::Client.stub(:new, fake_client) do
      silence_stdout do
        assert_nil build.send(:rpc_client)
      end
    end
  ensure
    Aegis.singleton_class.send(:remove_method, :config)
    Aegis.singleton_class.alias_method(:config, :_orig_config)
    Aegis.singleton_class.send(:remove_method, :_orig_config)
    Thread.current[:msf_rpc] = nil
    Thread.current[:msf_rpc_unavailable] = nil
  end

  # ── rpc_run_auxiliary busy-state path ──────────────────────────────────────

  test "rpc_run_auxiliary handles busy=true reads without exiting prematurely" do
    s = build(options: { safe_mode: true })
    s.define_singleton_method(:sleep) { |*| nil }
    Thread.current[:msf_aux_console] = nil
    drain = 0
    busy_then_done = [
      { "data" => "", "busy" => true },
      { "data" => "", "busy" => true },
      { "data" => "Auxiliary module execution completed\n", "busy" => false }
    ]
    handlers = {
      "console.create"  => -> { { "id" => "B1" } },
      "console.write"   => -> { nil },
      "console.read"    => -> {
        drain += 1
        drain <= 2 ? { "data" => "", "busy" => false } : (busy_then_done.shift || { "data" => "", "busy" => false })
      },
      "console.destroy" => -> { nil }
    }
    client = Object.new
    client.define_singleton_method(:call) { |method, *_a| handlers[method]&.call }
    silence_stdout do
      result = s.send(:rpc_run_auxiliary, client,
                      { "metasploit_module" => "auxiliary/x" }, "1.1.1.1", 445, nil, 10)
      refute result[:success]
    end
  end

  # ── attack_subprocess timeout path ────────────────────────────────────────

  test "attack_subprocess kills msfconsole on timeout" do
    s = build
    fake_master = Object.new
    fake_master.define_singleton_method(:readpartial) do |_n|
      sleep 0.05
      "[*] still running\n"
    end
    fake_master.define_singleton_method(:close) { }
    fake_slave = Object.new
    fake_slave.define_singleton_method(:close) { }
    killed = []

    s.stub(:with_clean_bundler_env, ->(&blk) { blk.call }) do
      PTY.stub(:spawn, [fake_master, fake_slave, 99999]) do
        Process.stub(:kill, ->(sig, pid) { killed << [sig, pid] }) do
          Process.stub(:wait, nil) do
            silence_stdout do
              s.send(:attack_subprocess,
                     { "metasploit_module" => "exploit/x", "name" => "T" },
                     "1.1.1.1", 80, nil, 0)
            end
          end
        end
      end
    end
    assert_includes killed.map(&:first), "TERM"
  end

  test "attack_subprocess uses safe-mode parser when safe_mode is set" do
    s = build(options: { safe_mode: true })
    fake_master = StringIO.new("[+] 1.1.1.1:445 - Vulnerable\n")
    fake_master.define_singleton_method(:readpartial) do |n|
      data = read(n)
      raise EOFError if data.nil? || data.empty?
      data
    end
    fake_master.define_singleton_method(:close) { }
    fake_slave = Object.new
    fake_slave.define_singleton_method(:close) { }

    s.stub(:with_clean_bundler_env, ->(&blk) { blk.call }) do
      PTY.stub(:spawn, [fake_master, fake_slave, 12345]) do
        Process.stub(:wait, nil) do
          silence_stdout do
            result = s.send(:attack_subprocess,
                            { "metasploit_module" => "auxiliary/x", "name" => "T" },
                            "1.1.1.1", 445, nil, 1)
            assert result[:success]
          end
        end
      end
    end
  end

  # ── DB helper rescue paths ─────────────────────────────────────────────────

  test "create_scan_target rescues SQL errors" do
    s = build(scan: scans(:running_scan))
    ActiveRecord::Base.connection.stub(:execute, ->(*) { raise "db gone" }) do
      silence_stdout do
        assert_nil s.send(:create_scan_target, assets(:asset_one).id)
      end
    end
  end

  test "complete_scan_target rescues SQL errors" do
    s = build(scan: scans(:running_scan))
    ActiveRecord::Base.connection.stub(:execute, ->(*) { raise "db gone" }) do
      silence_stdout do
        assert_nothing_raised { s.send(:complete_scan_target, 1, 1, 1) }
      end
    end
  end

  test "create_scan_exploit rescues SQL errors" do
    s = build(scan: scans(:running_scan))
    ActiveRecord::Base.connection.stub(:execute, ->(*) { raise "db gone" }) do
      silence_stdout do
        assert_nothing_raised do
          s.send(:create_scan_exploit, assets(:asset_one).id, exploits(:exploit_one).id, "success", 100)
        end
      end
    end
  end

  test "create_finding rescues SQL errors" do
    s = build(scan: scans(:running_scan))
    ActiveRecord::Base.connection.stub(:execute, ->(*) { raise "db gone" }) do
      silence_stdout do
        assert_nothing_raised do
          s.send(:create_finding, assets(:asset_one).id, exploits(:exploit_one).id,
                 "high", "ev", 22)
        end
      end
    end
  end

  # ── get_targets when use_agent is explicitly disabled ─────────────────────

  test "get_targets with use_agent: false bypasses agent lookup" do
    s = build(options: { use_agent: false }, asset_ids: [assets(:asset_one).id])
    silence_stdout do
      targets = s.send(:get_targets, organizations(:acme).id)
      assert targets.first
      assert_nil targets.first["proxy"]
    end
  end
end
