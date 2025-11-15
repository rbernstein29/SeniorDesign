# db.rb: This file handles interactions with the database, including database creation, inserts and queries

# Imports
require "pg"


# Create the PostgreSQL database, if it doesn't already exist, or clears the schema if it already exists
#
# Parameters:
#   int org_id: unique id relating to the organization creating the database
#   String org_name: name of the organization creating the database
#   String schema: defines the schema for the database
#
# Returns:
#   true: database created successfully
#   false: could not create/remove database

def create_schema(org_id: 0, org_name: "", schema: "my_schema")
    begin
        conn = get_connection

        # Clear schema if it already exists
        result = conn.exec_params(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = $1",
            [schema]
        )
    
        if result.ntuples > 0
            clear_schema(schema)
        end

        # Create schema
        conn.exec("CREATE SCHEMA IF NOT EXISTS my_schema")
        puts "Schema 'my_schema' created successfully"
    
        # Create user table in the schema
        conn.exec(%{
            CREATE TABLE IF NOT EXISTS my_schema.users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(100) NOT NULL,
                organization VARCHAR(100) NOT NULL,
                access_level VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        })
        
        # Create report table
        conn.exec(%{
            CREATE TABLE IF NOT EXISTS my_schema.reports (
                id SERIAL PRIMARY KEY,
                report VARCHAR(200) NOT NULL,
                org_id VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        })

        # Create network table
        conn.exec(%{
            CREATE TABLE IF NOT EXISTS my_schema.networks (
                id SERIAL PRIMARY KEY,
                ip VARCHAR(100) NOT NULL,
                domain VARCHAR(100),
                org_id VARCHAR(100) NOT NULL,
                os VARCHAR(100) NOT NULL,
                use_cases VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        })
    
        puts "Tables created successfully in schema"
        conn.close
        return true
    
    rescue PG::Error => e
        puts "Error: #{e.message}"
        conn&.close
        return false
    end
end


# Clears the given db schema
#
# Parameters:
#   String schema: the schema to be cleared
#
# Returns:
#   true: schema cleared successfully
#   false: could not clear schema

def clear_schema(schema)
    begin
        conn = get_connection
    
        sanitized_schema = PG::Connection.quote_ident(schema)
    
        # Drop schema and all its contents
        conn.exec("DROP SCHEMA IF EXISTS #{sanitized_schema} CASCADE")
        puts "Dropped schema '#{schema}' and all its contents"
    
        conn.close
        return true
    
    rescue PG::Error => e
        puts "Error: #{e.message}"
        conn&.close
        return false
    end
end


# Create a connection to the database
#
# Parameters:
#   String host: host server for the Postgres database
#   int port: open port for the server
#   dbname: name of the database
#   String user: username for the database
#   String pwd: password for the database (not required)
#
# Returns:
#   conn: the connection to the database
#   nil: connection could not be made

def get_connection(host: "localhost", port: 5432, dbname: "postgres", user: "postgres", pwd: "")
    begin
        conn = PG.connect(
        host: host,
        port: port,
        dbname: dbname,
        user: user,
        password: pwd
    )
    
        puts "Successfully connected to database: #{dbname}"
        return conn
    
    rescue PG::Error => e
        puts "Error connecting to database: #{e.message}"
        return nil
    end
end


# Write a user account to the db
#
# Parameters: 
#   String username: name of individual user
#   String user_email: name of the user organization
#   String user_password: email for user
#   String user_org: password for user
#   String user_access_level: access level of user (admin, read-only)
#   Strign schema: schema containing user table
#
# Returns:
#   inserted: inserted user entry
#   nil: the user could not be written to the database

def write_user(username, user_email, user_org, user_password, user_access_level, schema)
    begin
        conn = get_connection
    
        result = conn.exec_params(%{
            INSERT INTO #{schema}.users (username, email, organization, password, access_level, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING id, username, email, organization, password, access_level, created_at
        }, [username, user_email, user_org, user_password, user_access_level])
    
        inserted = result.first
        puts "Inserted user: ID=#{inserted['id']}, Username=#{inserted['username']}"
    
        conn.close
        return inserted
    
    rescue PG::Error => e
        puts "Error inserting user: #{e.message}"
        conn&.close
        return nil
    end
end


# Write a scan report to the db
#
# Parameters: 
#   String report: a JSON string of the scan report
#   int org_id: unique id relating to the organization who runs than scan
#   String schema: schema containing the report table
#
# Returns:
#   inserted: inserted report entry
#   nil: the report could not be written to the database

def write_report(report, org_id, schema)
    begin
        conn = get_connection
    
        result = conn.exec_params(%{
            INSERT INTO #{schema}.reports (report, org_id, created_at)
            VALUES ($1, $2, NOW())
            RETURNING id, report, org_id, created_at
        }, [report, org_id])
    
        inserted = result.first
        puts "Inserted report: ID=#{inserted['id']}, Organization=#{inserted['org_id']}"
    
        conn.close
        return inserted
    
    rescue PG::Error => e
        puts "Error inserting report: #{e.message}"
        conn&.close
        return nil
    end
end


# Write a network to the db
#
# Parameters: 
#   String ip_range: range of ips for the network
#   String domain_range: range of domains for the network (may be Nil)
#   String os: operating system of server
#   String use_cases: use cases for scanning
#   String org_id: unique organization id which owns the network
#   String schema: schema containing the network table
#
# Returns:
#   inserted: inserted network entry
#   nil: the user could not be written to the database

def write_network(ip_range, domain_range, os, use_cases, org_id, schema)
    begin
        conn = get_connection
    
        result = conn.exec_params(%{
            INSERT INTO #{schema}.networks (ip, domain, os, use_cases, org_id, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING id, ip, domain, os, use_cases, org_id, created_at
        }, [ip_range, domain_range, os, use_cases, org_id])
    
        inserted = result.first
        puts "Inserted network: ID=#{inserted['id']}, ip=#{inserted['ip_range']}, Organization=#{inserted['org_id']}"
    
        conn.close
        return inserted
    
    rescue PG::Error => e
        puts "Error inserting report: #{e.message}"
        conn&.close
        return nil
    end
end


# Retrieve a user from db
#
# Parameters:
#   int user_id: unique id for the desired report
#   String schema: schema containing user table
#
# Returns:
#   Strinf user: the desired user
#   nil: no user could be found for the given user_id or error during query

def get_user(user_id, schema)
    begin
        conn = get_connection
    
        result = conn.exec_params(
            "SELECT * FROM #{schema}.users WHERE id = $1",
            [user_id]
        )
    
        if result.ntuples > 0
            user_data = result.first
            conn.close
            return user_data
        else
            puts "No user found with ID #{user_id}"
            conn.close
            return nil
        end
    
    rescue PG::Error => e
        puts "Error: #{e.message}"
        conn&.close
        return nil
    end
end


# Retrieve a report instance from db
#
# Parameters:
#   int report_id: unique id for the desired report
#   String schema: schema containing report table
#
# Returns:
#   String report: the desired report
#   nil: no report could be found for the given report_id or error during query

def get_report(report_id, schema)
    begin
        conn = get_connection
    
        result = conn.exec_params(
            "SELECT * FROM #{schema}.reports WHERE id = $1",
            [report_id]
        )
    
        if result.ntuples > 0
            report_data = result.first
            conn.close
            return report_data
        else
            puts "No report found with ID #{report_id}"
            conn.close
            return nil
        end
    
    rescue PG::Error => e
        puts "Error: #{e.message}"
        conn&.close
        return nil
    end
end


# Retrieve a network instance from db
#
# Parameters:
#   int network_id: unique_id for the desired network
#   String schema, schema containing network table
#
# Returns:
#   String network: the desired network
#   nil: no network could be found for the given network_id or error during query

def get_network(network_id, schema)
    begin
        conn = get_connection
    
        result = conn.exec_params(
            "SELECT * FROM #{schema}.networks WHERE id = $1",
            [network_id]
        )
    
        if result.ntuples > 0
            network_data = result.first
            conn.close
            return network_data
        else
            puts "No network found with ID #{network_id}"
            conn.close
            return nil
        end
    
    rescue PG::Error => e
        puts "Error: #{e.message}"
        conn&.close
        return nil
    end
end


# Test method for db_driver.rb
# Allows for testing database functionality

def test
    puts get_network(1, "my_schema")
    puts get_network(2, "my_schema")
    puts get_network(3, "my_schema")
    puts get_network(40, "my_schema")
end

test