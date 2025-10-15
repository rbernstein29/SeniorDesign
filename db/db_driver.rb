'''
db.rb: This file handles interactions with the database, including inserts and queries
'''


'''
Write a completed scan report to the db

Parameters: 
    int report_id: unique id for a generated report
    int user_id: unique id relating to the admin user who runs than scan

Returns:
    1: report was successfully written to db
    Error: the report could not be written to the database
'''
def write_report(report_id, user_id)
  #
  #
    

'''
Write a user account to the db

Parameters: 
    String user_name: name of individual user
    String user_org: name of the user organization
    String ser_email: email for user
    String user_password: password for user
    String user_status: type of user (admin, read-only)

Returns:
    1: user was successfully written to db
    Error: the user could not be written to the database
'''
def write_user(user_name, user_org, user_email, user_password, user_status)
    #
    #


'''
Retrieve a user from db

Parameters:
    int user_id: unique id for the desired report
    
Returns:
    user: the desired user
    Nil: no user could be found for the given user_id
'''
def get_user(user_id)
    #
    #


'''
Retrieve a report from db

Parameters:
    int report_id: unique id for the desired report
    
Returns:
    report: the desired report
    Nil: no report could be found for the given report_id
'''
def get_report(report_id)
    #
    #
