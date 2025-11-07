# driver.rb: This file is responsible for executing the scans and exploits on a network


# Connect to the organization network from an IP or domain.
#
# Parameters:
#   String network: the IP or domain of the target network
#
# Returns:
#   1: succcessful connection
#   Error: connection unsuccessful

def connect_network(network)
    #
    #


# Disconnect from all current networks
#
# Returns:
#   1: successfully disconnected
#   Error: disconnection unsuccessful

def disconnect_network()
    #
    #


# Attacks a system vulnerability using a Metasploit exploit
#
# Parameters:
#   Exploit exploit: Metasploit exploit to attempt on the vulernability
#
# Returns:
#   1: exploit successful
#   0: exploit unsuccessful

def attack(exploit)
    #
    #


# Convert the results of a scan into a json string
#
# Parameters:
#   results_raw: the results of the scan
#
# Returns:
#   String results: the JSON string of the results

def result_to_json(results_raw)
    #
    #


# Call the metasploit framework
#
# Parameters:
#   int exploit_id: the id of the desired exploit
#
# Returns:
#   Exploit exploit: the desired exploit from the Metasploit framework

def get_exploit(exploit_id)
    #
    #


# Main body of the scan_driver. Responsible for running the scans and exploits

def main()
    #
    #