require "test_helper"

class Aegis::Msf::PlatformDirsTest < ActiveSupport::TestCase
  P = Aegis::Msf::PlatformDirs

  test "for_exploits maps windows" do
    assert_equal %w[windows multi], P.for_exploits("windows")
  end

  test "for_exploits maps linux" do
    assert_equal %w[linux unix multi], P.for_exploits("Linux")
  end

  test "for_exploits maps macos" do
    assert_equal %w[osx apple_ios multi], P.for_exploits(:macos)
  end

  test "for_exploits returns empty for unknown" do
    assert_equal [], P.for_exploits("solaris")
    assert_equal [], P.for_exploits(nil)
  end

  test "for_auxiliary_scanners maps windows" do
    assert_includes P.for_auxiliary_scanners("windows"), "scanner/smb"
  end

  test "for_auxiliary_scanners maps linux" do
    assert_includes P.for_auxiliary_scanners("linux"), "scanner/mysql"
  end

  test "for_auxiliary_scanners maps macos" do
    assert_equal %w[scanner/ssh scanner/http scanner/vnc], P.for_auxiliary_scanners("macos")
  end

  test "for_auxiliary_scanners falls back for unknown platform" do
    assert_equal %w[scanner/ssh scanner/ftp scanner/http], P.for_auxiliary_scanners("solaris")
    assert_equal %w[scanner/ssh scanner/ftp scanner/http], P.for_auxiliary_scanners(nil)
  end
end
