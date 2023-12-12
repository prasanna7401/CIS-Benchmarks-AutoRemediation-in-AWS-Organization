import boto3
import json
from cisPlaybook import *
import datetime


def lambda_handler(event, context):
    
    # Drop function if Compliancy status is already PASSED
    compliancy_status = event['detail']['findings'][0]['Compliance']['Status']
    if compliancy_status == "PASSED":
        print("This Control check has already PASSED. No remediation is needed.")
        return None
        
    workflow_status = event['detail']['findings'][0]['Workflow']['Status']
    if workflow_status == "NOTIFIED":
        print("This control has been already notified. If you still want to trigger this, use custom action")
        return None

    # --------- TARGET ACCOUNT DETAILS ---------
    target_account_id = event['detail']['findings'][0]['AwsAccountId']
    region = event['detail']['findings'][0]['Resources'][0]['Region']
    security_control_id = event['detail']['findings'][0]['Compliance']['SecurityControlId']

    # --------- MEMBER ACCOUNT ROLE ASSUMPTION ---------
    # Create a session using the current Lambda function's execution role
    session = boto3.Session()
    sts_client = session.client('sts')
    assumed_role = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{target_account_id}:role/CIS_Remediator_Role',
        RoleSessionName='CIS_Remediator_Session'
    )
    # Retrieve temporary credentials from the assumed role
    credentials = assumed_role['Credentials']
    # Create a new session using the temporary credentials and specified region
    target_session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )
    
    # --------- CIS REMEDIATION SNS NOTIFICATION ---------
    # Find SNS Topic in target account/region for SNS Notification
    sns_client = target_session.client('sns')
    response = sns_client.list_topics()
    topic_arns = [topic['TopicArn'] for topic in response['Topics']]
    for arn in topic_arns:
        if "CISRemediationSNSTopic" in arn:
            sns_topic_arn = arn
        


    # ------------------------------------ CIS CONTROL REMEDIATION FUNCTION CALLS ------------------------------------


    # --------------------------------- IAM CONTROLS ---------------------------------


    # CIS 1.1 (Maintain current contact details) 
        # Automated Check is not supported by AWS SecurityHub

    # CIS 1.2 (Ensure security contact information is registered) 
        # Automated Check is not supported by AWS SecurityHub

    # CIS 1.3 (Ensure security questions are registered in the AWS Account) 
        # Automated Check is not supported by AWS SecurityHub

    # CIS 1.4 (IAM root user access key should not exist) -- needs MANUAL remediation
    if(security_control_id=="IAM.4"):
        cis_1_4(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 1.5 (MFA should be enabled for the root user) -- needs MANUAL remediation
    if(security_control_id=="IAM.9"):
        cis_1_5(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 1.6 (Hardware MFA should be enabled for the root user) -- needs MANUAL remediation
    if(security_control_id=="IAM.6"):
        cis_1_6(event, target_session, region, target_account_id, sns_topic_arn)

    # CIS 1.7 (Eliminate the use of 'root' user for administrative and daily tasks)
        # For CISv1.4.0, Automated Check is not supported by AWS SecurityHub
        # This will be manually remediated by CIS 4.3 (Ensure a log metric filter and alarm exist for Usage of 'root' account)
    
    # CIS 1.8 (Ensure IAM password policy needs minimum password length of 14 or greater) -- AUTO-Remediation upon invoke
    if(security_control_id=="IAM.15"):
        cis_1_8(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 1.9 (Ensure IAM password policy prevents password reuse) -- AUTO-Remediation upon invoke
    if(security_control_id=="IAM.16"):
        cis_1_9(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 1.10 (MFA should be enabled for all IAM users that have a console password) -- needs MANUAL remediation
    if(security_control_id=="IAM.5"):
        cis_1_10(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 1.11 (Do not setup access keys while creating an IAM user that has console password)
        # Automated Check is not supported by AWS SecurityHub

    # CIS 1.12 (IAM user credentials unused for 45 days should be removed) -- AUTO-Remediation upon invoke
    if(security_control_id=="IAM.22"):
        cis_1_12(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 1.13 (Ensure that only one active IAM access key is present for a user)
        # Automated Check is not supported by AWS SecurityHub
    
    # CIS 1.14 (IAM users' access keys should be rotated every 90 days or less) -- AUTO-Remediation upon invoke
    if(security_control_id=="IAM.3"):
        cis_1_14(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 1.15 (Ensure that an IAM user receives permission only through groups, not directly attached)
        # Automated Check is not supported by AWS SecurityHub
    
    # CIS 1.16 (Customer-managed IAM policies should not allow full "*:*" administrative privileges) -- needs MANUAL remediation
    if(security_control_id=="IAM.1"):
        cis_1_16(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 1.17 (Ensure a support role has been created to manage incidents with AWS Support) -- AUTO-Remediation upon invoke
    if(security_control_id=="IAM.18"):
        support_role_name = "CIS_AWSSupportAccessRole" # Arbitrary name of the support role
        cis_1_17(event, target_session, region, target_account_id, sns_topic_arn, support_role_name)
    
    # CIS 1.18 (Ensure IAM instance roles are used for AWS resource access form IAM instances)
    # Automated Check is not supported by AWS SecurityHub

    # CIS 1.19 (Ensure that expired SSL/TLS Certificates stored in AWS IAM are removed)
        # Automated Check is not supported by AWS SecurityHub

    # CIS 1.20 (Ensure that IAM Access Analyzer is enabled for all regions)
        # Automated Check is not supported by AWS SecurityHub

    # CIS 1.21 (Ensure that IAM users are centrally managed via identity federation or AWS Organizations for multi-account environment)
        # Automated Check is not supported by AWS SecurityHub


    # --------------------------------- STORAGE CONTROLS ---------------------------------


    # CIS 2.1.1 (Ensure that all S3 buckets employ encryption-at-rest)
        # Automated Check is not supported by AWS SecurityHub

    # CIS 2.1.2 (S3 buckets should require requests to use Secure Socket Layer, set to deny HTTP requests) -- AUTO-Remediation upon invoke
    if(security_control_id=="S3.5"):
            bucket_name = event['detail']['findings'][0]['Resources'][0]['Details']['AwsS3Bucket']['Name']
            cis_2_1_2(event, target_session, region, target_account_id, sns_topic_arn, bucket_name)
    
    # CIS 2.1.5.1 (S3 Block Public Access setting should be enabled at account level) -- AUTO-Remediation upon invoke
    if(security_control_id=="S3.1"):
        cis_2_1_5_1(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 2.1.5.1 (S3 Block Public Access setting should be enabled at bucket level) -- AUTO-Remediation upon invoke
    if(security_control_id=="S3.8"):
        bucket_name = event['detail']['findings'][0]['Resources'][0]['Details']['AwsS3Bucket']['Name']
        cis_2_1_5_2(event, target_session, region, target_account_id, sns_topic_arn, bucket_name)
    
    # CIS 2.2.1 (EBS default encryption should be enabled) -- AUTO-Remediation upon invoke
    if(security_control_id=="EC2.7"):
        cis_2_2_1(event, target_session, region, target_account_id, sns_topic_arn)
    
    # CIS 2.3.1 (RDS DB instances should have encryption at-rest enabled) -- needs MANUAL remediation
    if(security_control_id=="RDS.3"):
        rds_id = event['detail']['findings'][0]['Resources'][0]['Details']['AwsRdsDbInstance']['DBInstanceIdentifier']
        cis_2_3_1(event, target_session, region, target_account_id, sns_topic_arn, rds_id)
    
    
    # --------------------------------- LOGGING CONTROLS ---------------------------------


    # CIS 3.1 (CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudTrail.1"):
        current_date = datetime.datetime.now().strftime("%Y%m%d")
        bucket_name = "cis_cloudtrail_bucket_"+current_date # Arbitrary & unique S3 bucket name
        trail_name = "CIS_MultiRegion_CloudTrail"
        cis_3_1_10_11(event, target_session, region, target_account_id, sns_topic_arn, bucket_name, trail_name)
    
    # CIS 3.2 (CloudTrail log file validation should be enabled) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudTrail.4"):
        trail_name = event['detail']['findings'][0]['Resources'][0]['Details']['AwsCloudTrailTrail']['Name']
        log_validation_status = event['detail']['findings'][0]['Resources'][0]['Details']['AwsCloudTrailTrail']['LogFileValidationEnabled']
        if not log_validation_status:
            cis_3_2(event, target_session, region, target_account_id, sns_topic_arn, trail_name)
    
    # CIS 3.3 (Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudTrail.6"):
        bucket_name = event['detail']['findings'][0]['Resources'][0]['Id'].split(":")[-1]
        cis_3_3(event, target_session, region, target_account_id, sns_topic_arn, bucket_name)
    
    # CIS 3.4 (CloudTrail trails should be integrated with Amazon CloudWatch Logs) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudTrail.5"):
        iam_rolename = 'CISCloudTrailToCloudWatchLogsRole' # Arbitrary Role used by CT to write on CW Log group
        trailname=event['detail']['findings'][0]['Resources'][0]['Details']['AwsCloudTrailTrail']['Name']
        cis_3_4(event, target_session, region, target_account_id, sns_topic_arn, iam_rolename, trailname)

    # CIS 3.5 (AWS Config should be enabled)
        # No automatic remediation exists in the suggested environment setup
        # This compliancy will fail when we disable config control checks in some regions for Global resources
    
    # CIS 3.6 (Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudTrail.7"):
        bucket_id = event['detail']['findings'][0]['Resources'][0]['Id']
        bucket_name = bucket_id.split(":")[-1]
        cis_3_6(event, target_session, region, target_account_id, sns_topic_arn, bucket_name)
    
    # CIS 3.7 (CloudTrail Logs should have encryption at-rest enabled) -- AUTO-Remediation upon invoke
        # Pre-requisite: This function will execute successfully only upon deploying CloudFormation Template for "CIS_CloudTrail_Encryption_KMS_Key_Deployment"
    if(security_control_id=="CloudTrail.2"):
        trailname=event['detail']['findings'][0]['Resources'][0]['Details']['AwsCloudTrailTrail']['Name']
        key_alias = "CIS_CloudTrail_Encryption" # Key created by CF Template
        cis_3_7(event, target_session, region, target_account_id, sns_topic_arn, trailname, key_alias)
    
    # CIS 3.8 (AWS KMS key rotation should be enabled) -- AUTO-Remediation upon invoke
    if(security_control_id=="KMS.4"):
        keyId= event['detail']['findings'][0]['ProductFields']['Resources:0/Id'].split('key/')[1]
        exclusion_keywords = ['PROD', 'Production', 'CRITICAL'] # Give the keywords in KMS Key description to avoid rotation
        cis_3_8(event, target_session, region, target_account_id, sns_topic_arn, exclusion_keywords, keyId)
    
    # CIS 3.9 (Ensure VPC Flow logging is enabled in all VPCs) -- AUTO-Remediation upon invoke
    if(security_control_id=="EC2.6"):
        iam_role_name = 'CIS_VPC_logging_CW' # Arbitrary role used to allow VPC to write on CW Log group
        vpc_id = event['detail']['findings'][0]['ProductFields']['Resources:0/Id'].split('/')[-1]
        cis_3_9(event, target_session, region, target_account_id, sns_topic_arn, iam_role_name, vpc_id)

    # CIS 3.10 (Ensure that object-level logging for write events is enabled for S3 buckets)
        # Control Check & Remediation is a part of CIS 3.1

    # CIS 3.11 (Ensure that object-level logging for read events is enabled for S3 buckets)
        # Control Check & Remediation is a part of CIS 3.1
    

    # --------------------------------- MONITORING CONTROLS ---------------------------------


    # CIS 4.1 (Ensure a log metric filter and alarm exist for Unauthorized API Calls)
        # Automated Check is not supported by AWS SecurityHub

    # CIS 4.2 (Ensure a log metric filter and alarm exist for Management console sign-in without MFA)
        # Automated Check is not supported by AWS SecurityHub

    # CIS 4.3 (Ensure a log metric filter and alarm exist for Usage of 'root' account) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.1"):
        log_group_name = "/aws/cloudtarail/management-events" # Arbitrary Log group that needs to be monitored
        alarm_sns_topic = sns_topic_arn # Arbitrary SNS Topic that needs to be notified during ALARM state
        threshold_value = 1 # Modify this based on requirement
        cis_4_3(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)

    # CIS 4.4 (Ensure a log metric filter and alarm exist for IAM policy changes) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.4"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_4(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)

    # CIS 4.5 (Ensure a log metric filter and alarm exist for CloudTrail configuration changes) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.5"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_5(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)
    
    # CIS 4.6 (Ensure a log metric filter and alarm exist for AWS Management Console authentication failures) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.6"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_6(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)
    
    # CIS 4.7 (Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.7"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_7(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)
    
    # CIS 4.8 (Ensure a log metric filter and alarm exist for S3 bucket policy changes) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.8"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_8(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)

    # CIS 4.9 (Ensure a log metric filter and alarm exist for AWS Config configuration changes) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.9"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_9(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)

    # CIS 4.10 (Ensure a log metric filter and alarm exist for Security Group changes) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.10"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_10(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)
    
    # CIS 4.11 (Ensure a log metric filter and alarm exist for changes to Network Access Control Lists) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.11"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_11(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)
    
    # CIS 4.12 (Ensure a log metric filter and alarm exist for changes to Network Gateways) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.12"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_12(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)
    
    # CIS 4.13 (Ensure a log metric filter and alarm exist for Route Table changes) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.13"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_13(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)
    
    # CIS 4.14 (Ensure a log metric filter and alarm exist for VPC changes) -- AUTO-Remediation upon invoke
    if(security_control_id=="CloudWatch.14"):
        log_group_name = "/aws/cloudtrail/management-events"
        alarm_sns_topic = sns_topic_arn
        threshold_value = 1
        cis_4_14(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value)
    
    # CIS 4.15 (Ensure a log metric filter and alarm exist for AWS Organization changes)
        # Automated Check is not supported by AWS SecurityHub
    

    # --------------------------------- NETWORKING CONTROLS ---------------------------------


    # CIS 5.1 (Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389) -- AUTO-Remediation upon invoke
        # Note: This code will additionally delete rules that allow "AnySource-AnyPort-AnyProtocol" or "AnySource-AllPort-AnyProtocol"
    if(security_control_id=="EC2.21"):
        nacl_id = event['detail']['findings'][0]['Resources'][0]['Details']['AwsEc2NetworkAcl']['NetworkAclId']
        associated_vpc = event['detail']['findings'][0]['Resources'][0]['Details']['AwsEc2NetworkAcl']['VpcId']
        cis_5_1(event, target_session, region, target_account_id, sns_topic_arn, nacl_id, associated_vpc)
    
    # CIS 5.2 (Security Groups should not allow ingress from 0.0.0.0/0 to port 22 or port 3389)
        # Not exists in CISv1.4.0
        # Remediation is covered under CIS 5.1

    # CIS 5.3 (VPC default security groups should not allow inbound or outbound traffic) -- AUTO-Remediation upon invoke
    if(security_control_id=="EC2.2"):
        vpc_id = event['detail']['findings'][0]['Resources'][0]['Details']["AwsEc2SecurityGroup"]["VpcId"]
        cis_5_3(event, target_session, region, target_account_id, sns_topic_arn, vpc_id)

    # CIS 5.4 (Ensure routing tables for VPC Peering are "least access")
        # Automated Check is not supported by AWS SecurityHub