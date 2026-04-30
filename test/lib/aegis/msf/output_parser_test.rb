require "test_helper"

class Aegis::Msf::OutputParserTest < ActiveSupport::TestCase
  test "parse_safe_mode flags success on [+] hit" do
    out = "[*] starting\n[+] 1.1.1.1:445 - Vulnerable to MS17-010\n"
    res = Aegis::Msf::OutputParser.parse_safe_mode(out, "1.1.1.1")
    assert res[:success]
    assert_match(/Vulnerable to MS17-010/, res[:evidence])
  end

  test "parse_safe_mode flags success on meaningful target IP line" do
    out = "[*] 1.1.1.1:445 - Service detected\n"
    res = Aegis::Msf::OutputParser.parse_safe_mode(out, "1.1.1.1")
    assert res[:success]
    assert_equal 1, res[:meaningful_ip_lines].size
  end

  test "parse_safe_mode rejects scanned-progress noise as evidence" do
    out = "[*] 1.1.1.1:445 - Scanned 1 of 1 hosts (100% complete)\n"
    res = Aegis::Msf::OutputParser.parse_safe_mode(out, "1.1.1.1")
    refute res[:success]
    assert_nil res[:evidence]
    assert_empty res[:meaningful_ip_lines]
  end

  test "parse_safe_mode evidence trimmed to 500 chars" do
    out = "[+] " + ("x" * 1000) + "\n"
    res = Aegis::Msf::OutputParser.parse_safe_mode(out, "1.1.1.1")
    assert res[:success]
    assert res[:evidence].length <= 500
  end

  test "parse_safe_mode handles regex-special target IP" do
    out = "[*] 10.0.0.1:80 - hit\n"
    res = Aegis::Msf::OutputParser.parse_safe_mode(out, "10.0.0.1")
    assert res[:success]
  end

  test "parse_exploit_mode succeeds when session opens" do
    out = "[*] Started reverse handler\n[*] Sending stage\n[*] Meterpreter session 1 opened (1.1.1.1)\n"
    res = Aegis::Msf::OutputParser.parse_exploit_mode(out)
    assert res[:success]
    assert_match(/Meterpreter session 1 opened/, res[:evidence])
  end

  test "parse_exploit_mode succeeds on Command shell session text" do
    out = "[*] Command shell session 2 opened\n"
    res = Aegis::Msf::OutputParser.parse_exploit_mode(out)
    assert res[:success]
  end

  test "parse_exploit_mode fails when no session opens" do
    out = "[*] Started reverse handler\n[-] Exploit aborted\n"
    res = Aegis::Msf::OutputParser.parse_exploit_mode(out)
    refute res[:success]
  end

  test "parse_exploit_mode caps evidence at 500 chars" do
    out = "[+] " + ("y" * 600) + " session 1 opened\n"
    res = Aegis::Msf::OutputParser.parse_exploit_mode(out)
    assert res[:success]
    assert_equal 500, res[:evidence].length
  end

  test "parse_exploit_mode returns nil evidence when nothing matches" do
    res = Aegis::Msf::OutputParser.parse_exploit_mode("totally empty\n")
    refute res[:success]
    assert_nil res[:evidence]
  end
end
