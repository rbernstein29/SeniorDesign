require 'socket'
require 'timeout'
require 'shellwords'

# Determines whether a host is reachable before launching a scan against it.
# Two probe paths:
#   - direct: ICMP ping → TCP connect on a small port set
#   - via SOCKS5 proxy: TCP connect through the proxy on a small port set
#
# Returns 1 (alive) or 0 (unreachable) — kept as integers because callers feed
# the result into existing connect_network() == 1 checks. All log output goes
# to puts so existing scan logs/operator expectations are unchanged.
module Aegis
  module Network
    module TcpProbe
      module_function

      def alive?(target_ip, proxy: nil)
        proxy ? socks5(target_ip, proxy) : direct(target_ip)
      end

      def direct(ip)
        if system("ping -c 1 -W 1 #{Shellwords.escape(ip)} > /dev/null 2>&1")
          puts "[+] #{ip} alive (ICMP ping)"
          return 1
        end

        Aegis.config.scan.tcp_probe_ports_direct.each do |test_port|
          begin
            Timeout.timeout(Aegis.config.scan.tcp_probe_timeout) { TCPSocket.new(ip, test_port).close }
            puts "[+] #{ip}:#{test_port} reachable (direct)"
            return 1
          rescue Errno::ECONNREFUSED
            puts "[+] #{ip}:#{test_port} refused — host is alive (direct)"
            return 1
          rescue => e
            puts "[-] #{ip}:#{test_port}: #{e.message}"
          end
        end

        puts "[-] #{ip} unreachable (direct)"
        0
      rescue => e
        puts "Connect check error for #{ip}: #{e.message}"
        0
      end

      def socks5(target_ip, proxy)
        socks_host, socks_port = parse_proxy(proxy)
        return 0 unless socks_host.present? && socks_port > 0

        Aegis.config.scan.tcp_probe_ports_proxy.each do |test_port|
          begin
            Timeout.timeout(Aegis.config.scan.tcp_probe_timeout) do
              sock = TCPSocket.new(socks_host, socks_port)
              sock.write("\x05\x01\x00")
              unless sock.read(2) == "\x05\x00"
                sock.close
                next
              end
              addr_bytes = target_ip.split('.').map(&:to_i).pack('C4')
              sock.write("\x05\x01\x00\x01" + addr_bytes + [test_port].pack('n'))
              resp = sock.read(10)
              sock.close
              if resp && resp.bytesize >= 2 && resp.getbyte(1) == 0
                puts "[+] #{target_ip}:#{test_port} reachable via agent proxy"
                return 1
              end
            end
          rescue Errno::ECONNREFUSED
            puts "[+] #{target_ip}:#{test_port} refused via proxy — host is alive"
            return 1
          rescue => e
            puts "[-] #{target_ip}:#{test_port} via proxy: #{e.message}"
          end
        end

        puts "[-] #{target_ip} unreachable via agent proxy"
        0
      rescue => e
        puts "Connect check error for #{target_ip}: #{e.message}"
        0
      end

      def parse_proxy(proxy)
        parts = proxy.sub(/\Asocks5:\/?\/?/, '').split(':')
        [parts[0], parts[1].to_i]
      end
    end
  end
end
