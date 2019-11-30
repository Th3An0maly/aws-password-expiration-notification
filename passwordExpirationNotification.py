from __future__ import print_function
import boto3
from botocore.exceptions import ClientError
import os
import json
import csv
from time import sleep
import datetime
import dateutil.parser
import sys

# Lambda Environment Variables
try: 
    REMINDER_THRESHOLD_DAYS = int(os.environ['reminderThresholdDays'])
    SEND_EMAIL = os.environ['sendEmail']
    FROM_EMAIL_ADDRESS = os.environ['fromEmailAddress']
    ENVIRONMENT = os.environ['environment']
    ADMIN_SUMMARY_ARN = os.environ['adminSummaryARN']
# If a key was not found, throw an error
except KeyError as e:
    print("Lambda Environment Variable required: " + e.message)
    sys.exit(1)

# Constants
SES_REGION = 'us-west-2'
DYNAMO_TABLE = 'UserEmailMap'
ADMIN_SUMMARY = ""
USER_SUMMARY = ""
emailSubject = "AWS Password Expiration Notice: {}"
passwordExpirationMessage = "{}, <br /><br />Your AWS Account '{}' in the '{}' environment, will expire in '{}' days.<br />Please login to the '{}' AWS Management Console and change your password.<br /><br />AWS Account: {}<br />Environment: {}<br />Expires in: {} days"
passwordPastExpirationMessage = "{},<br /><br />Your AWS Account '{}', in the '{}' environment, has expired.<br />Please contact an AWS administrator to reset your password.<br /><br />AWS Account: {}<br />Environment: {}<br />Status: EXPIRED"



# Entry point
def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, sort_keys=True))
    iamClient = boto3.client('iam')
    processPasswordExpirations(iamClient)
    return

def processPasswordExpirations(iamClient): 
    global ADMIN_SUMMARY
    ADMIN_SUMMARY = ""
    
    global USER_SUMMARY
    USER_SUMMARY = ""
    
    # Gets the "Expire passwords in X days" value
    maxPasswordAge = getMaxPasswordAge(iamClient)
    
    # The passwordLastChanged value is not available on the IAM user object.
    # The Credential Report must be used to get this value.
    credentialReport = getCredentialReport(iamClient)

    # Iterate through the credential report to determine password expiration
    for row in credentialReport:
        
        USER_SUMMARY = ""
        
        passwordEnabled = row['password_enabled']
        user = row['user']
        passwordLastChanged = row['password_last_changed']
        
        # Skip over accounts that have a password disabled (Service Accounts)
        if passwordEnabled != "true": continue
    
        emailMessage = ""
        
        # Get the user's email address.  
        # Do this upfront to provide the Admin report with people who are not setup, even if we will not be emailing them.
        userEmail = getUserEmailAddress(user)
        
        # isUserExpired returns true if the user's groups cannot be listed
        if isUserExpired(user) == 0:
            passwordExpirationDays = daysUntilExpiration(passwordLastChanged, maxPasswordAge)
            # If their password has completely expired, send a final notice ( == 0 ).  Do not continue to email them afterwards.
            if passwordExpirationDays <= 0:
                print("{} : User's password expired {} days ago.".format(user, passwordExpirationDays * -1))
                USER_SUMMARY = USER_SUMMARY + "\n{} : User's password expired {} days ago.".format(user, passwordExpirationDays * -1)
                if passwordExpirationDays == 0:
                    emailMessage = emailMessage + passwordPastExpirationMessage.format(user, user, ENVIRONMENT, user, ENVIRONMENT)
            elif passwordExpirationDays < REMINDER_THRESHOLD_DAYS :
                print("{} : User's password will expire in {} days.".format(user, passwordExpirationDays))
                emailMessage = emailMessage + passwordExpirationMessage.format(user, user, ENVIRONMENT, passwordExpirationDays, ENVIRONMENT, user, ENVIRONMENT, passwordExpirationDays)
        
        # Email the user
        if emailMessage != "" and userEmail != None:
                emailUser(userEmail, emailMessage)
                
        if USER_SUMMARY != "":
            USER_SUMMARY = "\n" + USER_SUMMARY
        
        ADMIN_SUMMARY = ADMIN_SUMMARY + USER_SUMMARY

    # print admin summary to log and push to admin summary arn
    print("Admin Summary: " + ADMIN_SUMMARY)
    if ADMIN_SUMMARY != "": sendAdminSummary()
    
    return

# Query the account's password policy for the password age. Return that number of days
def getMaxPasswordAge(iamClient):
    try: 
        response = iamClient.get_account_password_policy()
        return response['PasswordPolicy']['MaxPasswordAge']
    except ClientError as e:
        print("Error: getMaxPasswordAge: " + e.message)
        
# Get the credential report, download, and parse the CSV.
def getCredentialReport(iamClient):
    initialResponse = iamClient.generate_credential_report()
    if initialResponse['State'] == 'COMPLETE' :
        try: 
            response = iamClient.get_credential_report()
            credReportCSV = response['Content']
            # print(credReportCSV)
            reader = csv.DictReader(credReportCSV.splitlines())
            # print(reader.fieldnames)
            credReport = []
            for row in reader:
                credReport.append(row)
            return(credReport)
        except ClientError as e:
            print("Error: getCredentialReport: " + e.message)
    else:
        sleep(2)
        return getCredentialReport(iamClient)

# Check if user is expired
def isUserExpired(username):
    client = boto3.client('iam')
    try:
        response = client.list_groups_for_user(UserName=username)
    except ClientError as e:
        return True
    return False
    
# Calculate the days remaining until password expires
def daysUntilExpiration(passwordLastChanged, maxPasswordAge):
    # It's possible for passwordLastChanged to be either a string (to parse) or is already a datetime object.
    if type(passwordLastChanged) is str:
        passwordLastChangedDate=dateutil.parser.parse(passwordLastChanged).date()
    elif type(passwordLastChanged) is datetime.datetime:
        passwordLastChangedDate=passwordLastChanged.date()
    else:
        return -99999
    expires = (passwordLastChangedDate + datetime.timedelta(maxPasswordAge)) - datetime.date.today()
    return(expires.days)

def getUserEmailAddress(username):
    global USER_SUMMARY
    
    userEmail = None
    # Get the user from Dynamo
    dynamodbClient = boto3.client('dynamodb')
    
    try:
        response = dynamodbClient.get_item(
            TableName=DYNAMO_TABLE,
            Key={'username':{'S':username}}
        )
        userEmail = response['Item']['email']['S']
    except ClientError as e:
        print("Error: getUserEmailAddress: " + e.message)
    except:
        print("{} : User does not have an email mapped in the {} table.".format(username, DYNAMO_TABLE))
        USER_SUMMARY = USER_SUMMARY + "\n{} : User does not have an email mapped in the {} table.".format(username, DYNAMO_TABLE)
        
    return userEmail

def emailUser(emailAddress, message):
    global USER_SUMMARY
    
    if SEND_EMAIL.lower() != "true": return

    if message == "": return

    sesClient = boto3.client('ses',region_name=SES_REGION)
    
    subject = emailSubject.format(ENVIRONMENT)
    
    body = message
    
    try: 
        response = sesClient.send_raw_email(
            Source=FROM_EMAIL_ADDRESS,
            Destinations=[ emailAddress ],
            RawMessage={
                'Data': 
                    'From: ' + FROM_EMAIL_ADDRESS + '\n'
                    'To: ' + emailAddress + '\n'
                    'Subject: ' + subject + '\n'
                    'MIME-Version: 1.0\n'
                    'Content-Type: text/html;\n\n' +
                    body
            }
        )
        print("Password expiration email sent to {}".format(emailAddress))
        return
    except ClientError as e:
        USER_SUMMARY = USER_SUMMARY + "\nERROR: Password expiration email to {} was rejected: {}".format(emailAddress, e.message)
        
# Send the Summary of actions taken to the SNS topic
def sendAdminSummary():
    global ADMIN_SUMMARY
    snsClient = boto3.client('sns')

    message = "Password Expiration Notification Script: {} [{}]: ".format( ENVIRONMENT, datetime.datetime.now() ) + ADMIN_SUMMARY

    response = snsClient.publish(
        TopicArn=ADMIN_SUMMARY_ARN,
        Message=message,
        Subject="Password Expiration Notification Report: {} [{}]".format( ENVIRONMENT, datetime.date.today() )
    )