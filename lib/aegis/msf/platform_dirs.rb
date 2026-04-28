# Maps an OS platform name to the relative module subdirectories that
# ScanService and the exploit-count UI both need to walk. Centralized so the
# two stay in sync.
module Aegis
  module Msf
    module PlatformDirs
      module_function

      def for_exploits(platform)
        case platform&.to_s&.downcase
        when 'windows' then %w[windows multi]
        when 'linux'   then %w[linux unix multi]
        when 'macos'   then %w[osx apple_ios multi]
        else []
        end
      end

      def for_auxiliary_scanners(platform)
        case platform&.to_s&.downcase
        when 'windows' then %w[scanner/smb scanner/http scanner/ssh scanner/vnc]
        when 'linux'   then %w[scanner/ssh scanner/ftp scanner/http scanner/mysql scanner/postgres]
        when 'macos'   then %w[scanner/ssh scanner/http scanner/vnc]
        else                %w[scanner/ssh scanner/ftp scanner/http]
        end
      end
    end
  end
end
