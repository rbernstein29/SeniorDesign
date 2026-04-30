require "test_helper"
require "tmpdir"

class Aegis::MsfModuleParserTest < ActiveSupport::TestCase
  P = Aegis::MsfModuleParser

  test "severity_from_rank maps known ranks" do
    assert_equal "critical", P.severity_from_rank("excellent")
    assert_equal "critical", P.severity_from_rank("Great")
    assert_equal "high",     P.severity_from_rank("Good")
    assert_equal "medium",   P.severity_from_rank("normal")
    assert_equal "medium",   P.severity_from_rank("Average")
    assert_equal "low",      P.severity_from_rank("manual")
    assert_equal "low",      P.severity_from_rank(nil)
  end

  test "extract_quoted_value handles single-quoted bodies" do
    body = "'Name' => 'Hello World'"
    assert_equal "Hello World", P.extract_quoted_value(body, "Name")
  end

  test "extract_quoted_value handles double-quoted bodies" do
    body = "'Name' => \"Hello DQ\""
    assert_equal "Hello DQ", P.extract_quoted_value(body, "Name")
  end

  test "extract_quoted_value preserves embedded quotes of opposite style" do
    body = %q{'Name' => 'Samba "username map script" Cmd Exec'}
    assert_equal 'Samba "username map script" Cmd Exec', P.extract_quoted_value(body, "Name")
  end

  test "extract_quoted_value unescapes backslash escapes" do
    body = "'Name' => 'It\\'s working'"
    assert_equal "It's working", P.extract_quoted_value(body, "Name")
  end

  test "extract_quoted_value returns nil for missing key" do
    assert_nil P.extract_quoted_value("nothing relevant", "Name")
  end

  test "severity_from_file reads rank from a file" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, "Rank = ExcellentRanking\n")
      assert_equal "critical", P.severity_from_file(path)
    end
  end

  test "severity_from_file falls back to low for unreadable file" do
    assert_equal "low", P.severity_from_file("/no/such/file.rb")
  end

  test "metadata_full extracts name, description, cve, refs, date, authors" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, <<~RB)
        update_info(info,
          'Name'           => 'Awesome Exploit',
          'Description'    => %q{Multi-line desc.},
          'References'     => [
            ['CVE', '2026-1234'],
            ['URL', 'https://example.com']
          ],
          'DisclosureDate' => '2026-04-01',
          'Authors'        => ['alice', 'bob']
        )
      RB
      meta = P.metadata_full(path)
      assert_equal "Awesome Exploit", meta[:name]
      assert_equal "Multi-line desc.", meta[:description]
      assert_equal "CVE-2026-1234", meta[:cve_id]
      assert_equal Date.new(2026, 4, 1), meta[:disclosure_date]
      assert_equal "alice, bob", meta[:authors]
      assert(meta[:references].any? { |r| r["type"] == "URL" })
    end
  end

  test "metadata_full prefixes raw CVE if missing prefix" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, "['CVE', '2026-9999']")
      assert_equal "CVE-2026-9999", P.metadata_full(path)[:cve_id]
    end
  end

  test "metadata_full keeps prefixed CVE intact" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, "['CVE', 'CVE-2026-7777']")
      assert_equal "CVE-2026-7777", P.metadata_full(path)[:cve_id]
    end
  end

  test "metadata_full handles unparseable disclosure date as nil" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, "'DisclosureDate' => 'not a date'")
      assert_nil P.metadata_full(path)[:disclosure_date]
    end
  end

  test "metadata_full falls back to single Author key" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, "'Author' => 'solo dev'")
      assert_equal "solo dev", P.metadata_full(path)[:authors]
    end
  end

  test "metadata_lite reads name, severity, cve and description" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, <<~RB)
        Rank = GoodRanking
        update_info(info,
          'Name' => 'Lite Mod',
          'Description' => %q{Lite-only desc.},
          'References' => [['CVE', '2026-0001']]
        )
      RB
      meta = P.metadata_lite(path)
      assert_equal "Lite Mod", meta[:name]
      assert_equal "high", meta[:severity]
      assert_equal "CVE-2026-0001", meta[:cve_id]
      assert_equal "Lite-only desc.", meta[:description]
    end
  end

  test "metadata_lite truncates long descriptions to 500 chars" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "m.rb")
      File.write(path, "'Description' => %q{#{'x' * 800}}")
      assert_equal 500, P.metadata_lite(path)[:description].length
    end
  end

  test "metadata_lite accepts injected content kwarg" do
    meta = P.metadata_lite("/tmp/ignored", content: "'Name' => 'Direct'")
    assert_equal "Direct", meta[:name]
  end

  test "metadata_lite handles unreadable file (returns severity low)" do
    meta = P.metadata_lite("/no/such/path.rb")
    assert_nil meta[:name]
    assert_equal "low", meta[:severity]
  end
end
