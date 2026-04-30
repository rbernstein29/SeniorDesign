require "test_helper"
require "socket"

class Aegis::Network::TcpProbeTest < ActiveSupport::TestCase
  T = Aegis::Network::TcpProbe

  def silence
    orig = $stdout
    $stdout = StringIO.new
    yield
  ensure
    $stdout = orig
  end

  def with_scan_config(direct: [22], proxy: [22], timeout: 1)
    scan_stub = Struct.new(:tcp_probe_ports_direct, :tcp_probe_ports_proxy, :tcp_probe_timeout)
                       .new(direct, proxy, timeout)
    config_stub = Struct.new(:scan).new(scan_stub)
    Aegis.singleton_class.alias_method(:_orig_config, :config)
    Aegis.define_singleton_method(:config) { config_stub }
    yield
  ensure
    Aegis.singleton_class.send(:remove_method, :config)
    Aegis.singleton_class.alias_method(:config, :_orig_config)
    Aegis.singleton_class.send(:remove_method, :_orig_config)
  end

  test "parse_proxy strips socks5 scheme and splits host:port" do
    assert_equal ["10.0.0.1", 1080], T.parse_proxy("socks5://10.0.0.1:1080")
    assert_equal ["10.0.0.1", 1080], T.parse_proxy("10.0.0.1:1080")
  end

  test "alive? routes to direct when no proxy is given" do
    T.stub(:direct, ->(ip) { :went_direct }) do
      assert_equal :went_direct, T.alive?("1.2.3.4")
    end
  end

  test "alive? routes to socks5 when a proxy is given" do
    T.stub(:socks5, ->(ip, proxy) { :went_socks }) do
      assert_equal :went_socks, T.alive?("1.2.3.4", proxy: "socks5://1.1.1.1:1080")
    end
  end

  test "direct returns 1 when ICMP ping succeeds" do
    T.stub(:system, true) do
      silence { assert_equal 1, T.direct("1.2.3.4") }
    end
  end

  test "direct returns 1 on TCP connect when ping fails" do
    server = TCPServer.new("127.0.0.1", 0)
    port   = server.addr[1]
    with_scan_config(direct: [port], timeout: 2) do
      T.stub(:system, false) do
        silence { assert_equal 1, T.direct("127.0.0.1") }
      end
    end
  ensure
    server&.close
  end

  test "direct treats ECONNREFUSED as alive" do
    with_scan_config(direct: [1]) do
      T.stub(:system, false) do
        TCPSocket.stub(:new, ->(*) { raise Errno::ECONNREFUSED }) do
          silence { assert_equal 1, T.direct("127.0.0.1") }
        end
      end
    end
  end

  test "direct returns 0 when no ports respond" do
    with_scan_config(direct: [1]) do
      T.stub(:system, false) do
        TCPSocket.stub(:new, ->(*) { raise Timeout::Error }) do
          silence { assert_equal 0, T.direct("127.0.0.1") }
        end
      end
    end
  end

  test "direct rescues outer-block errors and returns 0" do
    T.stub(:system, ->(*) { raise "outer boom" }) do
      silence { assert_equal 0, T.direct("127.0.0.1") }
    end
  end

  test "socks5 returns 0 for invalid proxy string" do
    silence do
      assert_equal 0, T.socks5("127.0.0.1", "socks5://:0")
    end
  end

  test "socks5 returns 1 when SOCKS proxy reports success" do
    fake_sock = Object.new
    writes = []
    reads  = ["\x05\x00", "\x05\x00\x00\x01" + "\x00" * 6]
    fake_sock.define_singleton_method(:write) { |x| writes << x }
    fake_sock.define_singleton_method(:read)  { |_n| reads.shift }
    fake_sock.define_singleton_method(:close) { }

    with_scan_config(proxy: [80]) do
      TCPSocket.stub(:new, ->(*) { fake_sock }) do
        silence { assert_equal 1, T.socks5("1.2.3.4", "socks5://1.1.1.1:1080") }
      end
    end
  end

  test "socks5 retries when SOCKS handshake doesn't return success bytes" do
    fake = Object.new
    fake.define_singleton_method(:write) { |_x| }
    fake.define_singleton_method(:read)  { |_n| "\x05\x99" }
    fake.define_singleton_method(:close) { }

    with_scan_config(proxy: [80]) do
      TCPSocket.stub(:new, ->(*) { fake }) do
        silence { assert_equal 0, T.socks5("1.2.3.4", "socks5://1.1.1.1:1080") }
      end
    end
  end

  test "socks5 treats ECONNREFUSED as alive" do
    with_scan_config(proxy: [80]) do
      TCPSocket.stub(:new, ->(*) { raise Errno::ECONNREFUSED }) do
        silence { assert_equal 1, T.socks5("1.2.3.4", "socks5://1.1.1.1:1080") }
      end
    end
  end

  test "socks5 returns 0 on timeout/other errors" do
    with_scan_config(proxy: [80]) do
      TCPSocket.stub(:new, ->(*) { raise Timeout::Error }) do
        silence { assert_equal 0, T.socks5("1.2.3.4", "socks5://1.1.1.1:1080") }
      end
    end
  end

  test "socks5 rescues outer-block errors and returns 0" do
    T.stub(:parse_proxy, ->(*) { raise "outer boom" }) do
      silence { assert_equal 0, T.socks5("1.2.3.4", "socks5://1.1.1.1:1080") }
    end
  end
end
