# db.rb: This file handles interactions with the database, including database creation, inserts and queries


# Create the PostgreSQL database, if it doesn't already exist, or delete the database if it already exists
#
# Parameters:
#   int org_id: unique id relating to the organization creating the database
#   String org_name: name of the organization creating the database
#   String org_structure: defines the structure for the organization
#
# Returns:
#   1: database created successfully
#   2: database deleted successfully
#   Error: could not create/remove database

def create_db(org_id, org_name, org_structure)
    #
    #


# Create a connection to the database
#
# Parameters:
#   String uname: username for the database
#   String pwd: password for the database
#
# Returns:
#   1: successfully connected to the database
#   Error: connection could not be made

def get_connection(uname, pwd)
    #
    #


# Write a user account to the db
#
# Parameters: 
#   String user_name: name of individual user
#   String user_org: name of the user organization
#   String user_email: email for user
#   String user_password: password for user
#   String user_status: type of user (admin, read-only)
#
# Returns:
#   1: user was successfully written to db
#   Error: the user could not be written to the database

def write_user(user_name, user_org, user_email, user_password, user_status)
    #
    #


# Write a scan report to the db
#
# Parameters: 
#   String report: a JSON string of the scan report
#   int org_id: unique id relating to the organization who runs than scan
#
# Returns:
#   1: report was successfully written to db
#   Error: the report could not be written to the database

def write_report(report, org_id)
  #
  #


# Write a network to the db
#
# Parameters: 
#   String ip_range: range of ips for the network
#   String domain_range: range of domains for the network (may be Nil)
#   String os: operating system of server
#   String use_cases: use cases for scanning
#   String org_id: unique organization id which owns the network
#
# Returns:
#   1: user was successfully written to db
#   Error: the user could not be written to the database

def write_network(ip_range, domain_range, os, use_cases, org_id)
    #
    #


# Retrieve a user from db
#
# Parameters:
#   int user_id: unique id for the desired report
#
# Returns:
#   String user: the desired user
#   Nil: no user could be found for the given user_id

def get_user(user_id)
    #
    #


# Retrieve a report instance from db
#
# Parameters:
#   int report_id: unique id for the desired report
#
# Returns:
#   String report: the desired report
#   Nil: no report could be found for the given report_id

def get_report(report_id)
    #
    #


# Retrieve a network instance from db
#
# Parameters:
#   int network_id: unique_id for the desired network
#
# Returns:
#   String network: the desired network
#   Nil: no network could be found for the given network_id

def get_network(network_id)
    #
    #