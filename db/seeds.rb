# This file should ensure the existence of records required to run the application in every environment (production,
# development, test). The code here should be idempotent so that it can be executed at any point in every environment.
# The data can then be loaded with the bin/rails db:seed command (or created alongside the database with db:setup).

exploits_data = [
  # Critical severity
  {
    exploit_id:         'MS17-010',
    name:               'EternalBlue SMB RCE',
    description:        'Remote code execution via SMBv1 buffer overflow. Affects unpatched Windows 7/Server 2008 R2.',
    severity:           'critical',
    cve_id:             'CVE-2017-0144',
    metasploit_module:  'exploit/windows/smb/ms17_010_eternalblue'
  },
  {
    exploit_id:         'CVE-2021-44228',
    name:               'Log4Shell RCE',
    description:        'JNDI injection in Apache Log4j 2.x allows unauthenticated RCE via crafted log messages.',
    severity:           'critical',
    cve_id:             'CVE-2021-44228',
    metasploit_module:  'exploit/multi/http/log4shell_header_injection'
  },
  {
    exploit_id:         'CVE-2017-5638',
    name:               'Apache Struts2 RCE',
    description:        'Content-Type header injection in Apache Struts2 allows unauthenticated RCE.',
    severity:           'critical',
    cve_id:             'CVE-2017-5638',
    metasploit_module:  'exploit/multi/http/struts2_content_type_ognl'
  },
  {
    exploit_id:         'CVE-2019-0708',
    name:               'BlueKeep RDP RCE',
    description:        'Pre-authentication RCE in Windows Remote Desktop Services (RDP). Wormable.',
    severity:           'critical',
    cve_id:             'CVE-2019-0708',
    metasploit_module:  'exploit/windows/rdp/cve_2019_0708_bluekeep_rce'
  },
  {
    exploit_id:         'CVE-2021-34527',
    name:               'PrintNightmare RCE',
    description:        'Windows Print Spooler privilege escalation / RCE via crafted DLL.',
    severity:           'critical',
    cve_id:             'CVE-2021-34527',
    metasploit_module:  'exploit/windows/local/cve_2021_34527_printnightmare'
  },
  # High severity
  {
    exploit_id:         'CVE-2018-11776',
    name:               'Apache Struts2 Namespace RCE',
    description:        'Namespace-based OGNL injection in Apache Struts2 when alwaysSelectFullNamespace is true.',
    severity:           'high',
    cve_id:             'CVE-2018-11776',
    metasploit_module:  'exploit/multi/http/struts2_namespace_ognl'
  },
  {
    exploit_id:         'CVE-2020-1472',
    name:               'Zerologon Netlogon Priv Esc',
    description:        'Cryptographic flaw in MS-NRPC allows unauthenticated attacker to become domain admin.',
    severity:           'high',
    cve_id:             'CVE-2020-1472',
    metasploit_module:  'exploit/windows/dcerpc/cve_2020_1472_zerologon'
  },
  {
    exploit_id:         'CVE-2019-11510',
    name:               'Pulse Secure VPN Arbitrary File Read',
    description:        'Unauthenticated arbitrary file read in Pulse Secure SSL VPN, exposing credentials.',
    severity:           'high',
    cve_id:             'CVE-2019-11510',
    metasploit_module:  'auxiliary/scanner/http/pulse_secure_file_read'
  },
  {
    exploit_id:         'MS08-067',
    name:               'Conficker / NetAPI RCE',
    description:        'Stack overflow in Windows Server service NetAPI DLL allows unauthenticated RCE.',
    severity:           'high',
    cve_id:             'CVE-2008-4250',
    metasploit_module:  'exploit/windows/smb/ms08_067_netapi'
  },
  # Medium severity
  {
    exploit_id:         'CVE-2014-6271',
    name:               'Shellshock Bash RCE',
    description:        'Bash processes trailing strings after function definitions, enabling command injection via environment variables.',
    severity:           'medium',
    cve_id:             'CVE-2014-6271',
    metasploit_module:  'exploit/multi/http/apache_mod_cgi_bash_env_exec'
  },
  {
    exploit_id:         'CVE-2017-9791',
    name:               'Apache Struts REST Plugin RCE',
    description:        'OGNL expression injection via the REST plugin in Apache Struts2.',
    severity:           'medium',
    cve_id:             'CVE-2017-9791',
    metasploit_module:  'exploit/multi/http/struts2_rest_xstream'
  },
  # Low severity
  {
    exploit_id:         'CVE-2011-2523',
    name:               'vsftpd 2.3.4 Backdoor',
    description:        'Malicious backdoor introduced into vsftpd 2.3.4 source distribution; triggers shell on port 6200.',
    severity:           'low',
    cve_id:             'CVE-2011-2523',
    metasploit_module:  'exploit/unix/ftp/vsftpd_234_backdoor'
  },
  {
    exploit_id:         'CVE-2004-2687',
    name:               'distcc Daemon Command Execution',
    description:        'distcc 2.x daemon allows remote command execution via crafted compilation request.',
    severity:           'low',
    cve_id:             'CVE-2004-2687',
    metasploit_module:  'exploit/unix/misc/distcc_exec'
  }
]

exploits_data.each do |attrs|
  Exploit.find_or_create_by!(exploit_id: attrs[:exploit_id]) do |e|
    e.name               = attrs[:name]
    e.description        = attrs[:description]
    e.severity           = attrs[:severity]
    e.cve_id             = attrs[:cve_id]
    e.metasploit_module  = attrs[:metasploit_module]
  end
end

puts "Seeded #{exploits_data.count} exploit records."
