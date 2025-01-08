import datetime
import json
import botocore

# Send a email notification to Security Admin about Remediation Status
def email_notification(target_session, sns_topic_arn, subject, message):
    sns_client = target_session.client('sns')
    sns_client.publish(TopicArn=sns_topic_arn, Subject=subject, Message=message)
    print(f"Email Notification has been published to SNS topic: {sns_topic_arn}")


# Update SecurityHub WorkFlow Status from NEW to NOTIFIED
def auto_update_securityhub_status(event, target_session):
    securityhub_client = target_session.client('securityhub')
    control_finding_id = event['detail']['findings'][0]['Id']
    
    response = securityhub_client.batch_update_findings(
        FindingIdentifiers=[
            {
                'Id': control_finding_id,
                'ProductArn': event['detail']['findings'][0]['ProductArn']
            },
        ],
        Workflow={ 
            'Status': 'NOTIFIED'
        },
        Note={
            'Text': 'Auto-remediation task has been invoked',
            'UpdatedBy': 'CIS Remediation Master'
        }
    )

    print('SecurityHub Finding WorkFlow status updated as NOTIFIED after AUTO-remediation')
    
def manual_update_securityhub_status(event, target_session):
    securityhub_client = target_session.client('securityhub')
    control_finding_id = event['detail']['findings'][0]['Id']
    
    response = securityhub_client.batch_update_findings(
        FindingIdentifiers=[
            {
                'Id': control_finding_id,
                'ProductArn': event['detail']['findings'][0]['ProductArn']
            },
        ],
        Workflow={ 
            'Status': 'NOTIFIED'
        },
        Note={
            'Text': 'There is no auto-remediation for this control. Please perform manual remediation',
            'UpdatedBy': 'CIS Remediation Master'
        }
    )

    print('SecurityHub Finding WorkFlow status updated as NOTIFIED after MANUAL remediation')


# -------------------------------------------- CIS REMEDIATION FUNCTIONS --------------------------------------------


# --------------------------------- IAM CONTROLS ---------------------------------


# CIS 1.1 (Maintain current contact details)
    # Automated Check is not supported by AWS SecurityHub


# CIS 1.2 (Ensure security contact information is registered)
    # Automated Check is not supported by AWS SecurityHub


# CIS 1.3 (Ensure security questions are registered in the AWS Account)
    # Automated Check is not supported by AWS SecurityHub


# CIS 1.4 (IAM root user access key should not exist)
def cis_1_4(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']

    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")
    
    # --- REMEDIATION CODE ---
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
    
    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Root Account Violation"
    message = f"""
    Your Organization Security Administrator has requested for a remediation to the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account:{target_account_id}
    Region: {region}
    
    Steps to perform remediation:
        1. Remove Root user access key in your account"""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    manual_update_securityhub_status(event, target_session)


# CIS 1.5 (MFA should be enabled for the root user)
def cis_1_5(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']

    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")
    
    # --- REMEDIATION CODE --- 
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Root Account Violation"
    message = f"""
    Your Organization Security Administrator has requested for a remediation to the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account:{target_account_id}
    Region: {region}
    
    Steps to perform remediation:
        1. Enable MFA for root user"""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    manual_update_securityhub_status(event, target_session)


# CIS 1.6 (Hardware MFA should be enabled for the root user)
def cis_1_6(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")
    
    # --- REMEDIATION CODE ---
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
    
    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Root Account Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Steps to perform remediation:
        1. Enable Hardware MFA for root user"""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    manual_update_securityhub_status(event, target_session)


# CIS 1.7 (Eliminate the use of 'root' user for administrative and daily tasks) 
        # Not exists in CISv1.4.0
        # Remediation is covered by CIS 4.3 (Ensure a log metric filter and alarm exist for Usage of 'root' account)


# CIS 1.8 (Ensure IAM password policy requires minimum password length of 14 or greater)
def cis_1_8(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    iam_client = target_session.client('iam')

    # Update the password policy
    try:
        password_policy = iam_client.get_account_password_policy()
        if password_policy['PasswordPolicy']['MinimumPasswordLength'] < 14:
            password_policy['PasswordPolicy']['MinimumPasswordLength'] = 14
            iam_client.update_account_password_policy(**password_policy['PasswordPolicy'])
            
    except: # if password policy does not exists
        # Create a new password policy
        password_policy = {
            'MinimumPasswordLength': 14,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'RequireNumbers': True,
            'RequireSymbols': True,
            'MaxPasswordAge': 90
            # Add other desired password policy settings here
        }
        iam_client.update_account_password_policy(**password_policy)
    finally:
        print("Password policy has been successfully updated to ensure minimum length")
        
    # --- SNS EMAIL INFO ---  
    subject = "CIS Control Remediation - Password Policy Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Remediation Action Taken: The password policy has been updated to ensure minimum length of 14."""
        
    email_notification(target_session, sns_topic_arn, subject, message) 
    auto_update_securityhub_status(event, target_session)


# CIS 1.9 (Ensure IAM password policy prevents password reuse)
def cis_1_9(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    iam_client = target_session.client('iam')

    # Update the password policy
    try:
        password_policy = iam_client.get_account_password_policy()
        if password_policy['PasswordPolicy']['PasswordReusePrevention'] != 1:
            password_policy['PasswordPolicy']['PasswordReusePrevention'] = 1
            iam_client.update_account_password_policy(**password_policy['PasswordPolicy'])
            
    except: # if password policy does not exists
        # Create a new password policy
        password_policy = {
            'MinimumPasswordLength': 14,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'RequireNumbers': True,
            'RequireSymbols': True,
            'MaxPasswordAge': 90,
            'PasswordReusePrevention' : 1
            # Add other desired password policy settings here
        }
        iam_client.update_account_password_policy(**password_policy)
    finally:
        print("Password policy has been updated to avoid reuse.")
        
    
    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Password Policy Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Remediation Action Taken: Changed the password policy to prevent reuse."""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)
    

# CIS 1.10 (MFA should be enabled for all IAM users that have a console password)
def cis_1_10(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - IAM Users Access Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Steps to perform remediation:
        1. Enable MFA for all IAM users that have a console password"""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    manual_update_securityhub_status(event, target_session)


# CIS 1.11 (Do not setup access keys while creating an IAM user that has console password)
    # Automated Check is not supported by AWS SecurityHub


# CIS 1.12 (IAM user credentials unused for 45 days should be removed)
def cis_1_12(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    iam_client = target_session.client('iam')
    
    #### Remove the below fresh execution later. Use inputs from SecurityHub Finding JSON inputs
    # Get the current date and time
    current_time = datetime.datetime.now(datetime.timezone.utc)

    # List all IAM users
    response = iam_client.list_users()
    
    # Dictionary to store deleted access keys for each user
    deleted_access_keys={}

    # Iterate over the users and check their access key last used date
    for user in response['Users']:
        user_name = user['UserName']
        access_keys = iam_client.list_access_keys(UserName=user_name)['AccessKeyMetadata']
        
        deleted_keys_for_user = [] # stores basic info of deleted user access keys
        
        for key in access_keys:
            access_key_id = key['AccessKeyId']
            access_key_last_used = iam_client.get_access_key_last_used(AccessKeyId=access_key_id).get('AccessKeyLastUsed')
            last_used = access_key_last_used.get('LastUsedDate') if access_key_last_used else None 
            
            # Check if the access key exists and has not been used for more than 45 days & delete if exists
            if last_used is None or (current_time - last_used).days > 45:
                iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
                print("Access key {} for user {} has been deleted.".format(access_key_id, user_name))
                deleted_keys_for_user.append(access_key_id)
                
        # Add the list of deleted access keys to the dictionary for the current user
        deleted_access_keys[user_name] = deleted_keys_for_user 
    
    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Unused Access Key Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: The following user access keys have been DELETED ~
    {deleted_access_keys}"""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 1.13 (Ensure that only one active IAM access key is present for a user)
        # Automated Check is not supported by AWS SecurityHub


# CIS 1.14 (IAM users' access keys should be rotated every 90 days or less)
def cis_1_14(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    iam_client = target_session.client('iam')
    
    #### Remove the below fresh execution later. Use inputs from SecurityHub Finding JSON inputs
    # Get the current date and time
    current_time = datetime.datetime.now(datetime.timezone.utc)

    # List all IAM users
    response = iam_client.list_users()
    
    # Dictionary to store deleted access keys for each user
    disabled_access_keys={}

    # Check each users' access key last used date
    for user in response['Users']:
        user_name = user['UserName']
        access_keys = iam_client.list_access_keys(UserName=user_name)['AccessKeyMetadata']
        
        disabled_keys_for_user = [] # stores basic info of deleted user access keys
        
        for key in access_keys:
            access_key_id = key['AccessKeyId']
            last_rotated_time = key['CreateDate']   
            # Age of the key
            days_since_rotation = (current_time - last_rotated_time).days
            # Disable keys older than 90 days
            if days_since_rotation > 90:
                iam_client.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status='Inactive')
                print("Access key {} for user {} has been disabled.".format(access_key_id, user_name))
                disabled_keys_for_user.append(access_key_id)
        # Add the list of deleted access keys to the dictionary for the current user
        disabled_access_keys[user_name] = disabled_keys_for_user 
    
    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Access Key Rotation Policy Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: The following IAM user access keys have been DISABLED ~
    {disabled_access_keys}"""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 1.16 (Customer-managed IAM policies should not allow full "*:*" administrative privileges)
def cis_1_16(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")
    
    #### Remove the below fresh execution later. Use inputs from SecurityHub Finding JSON inputs
    iam_client = target_session.client('iam')

    # List all customer-managed policies
    response = iam_client.list_policies(Scope='Local', OnlyAttached=False)

    # Check for policies with open admin access to AWS services
    policies_with_full_admin_privileges = []

    def check_policy_permissions(policy_document):
        # Check if the policy document grants full administrative privileges
        try:
            for permission in policy_document['Statement']:
                if permission['Effect'] == "Allow" and permission['Action'] == "*" and permission['Resource'] == "*":
                    return True
            return False
        except Exception as e:
            print(f"Error in policy: {policy_document}\nError message: {str(e)}")
            return False

    for policy in response['Policies']:
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']

        # Get the policy document
        response = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy['DefaultVersionId'])
        policy_document = response['PolicyVersion']['Document']

        # Check if the policy grants full administrative privileges
        if check_policy_permissions(policy_document):
            print(f'{policy_name} has full * access')
            policies_with_full_admin_privileges.append(policy_name)


    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Policy with Open Administrator Access"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Steps to perform remediation:
        1. Remove "*" allow access for Action/Resource in policies ~ {policies_with_full_admin_privileges}"""
         
    email_notification(target_session, sns_topic_arn, subject, message)
    manual_update_securityhub_status(event, target_session)


# CIS 1.17 (Ensure a support role has been created to manage incidents with AWS Support)
def cis_1_17(event, target_session, region, target_account_id, sns_topic_arn, support_role_name):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")
    
    # --- REMEDIATION CODE ---
    iam_client = target_session.client('iam')
    
    # Check if the user-given role already exists
    try:
        iam_client.get_role(RoleName=support_role_name)
        print(f"Support role {support_role_name} already exists.")
        
    except:
        # Create the support role
        iam_client.create_role( 
            RoleName=support_role_name,
            AssumeRolePolicyDocument="""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "support.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }""",
            Description="Role for managing incidents with AWS Support"
        )
        
        iam_client.attach_role_policy(
            RoleName=support_role_name,
            PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess'
        )
        print(f"Support role {support_role_name} created successfully.")

    
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Missing Support Role"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
        
    Remediation Action Taken: {support_role_name} has been created. Please attach it to the user who has to manage AWS support tickets"""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


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


# CIS 2.1.2 (S3 buckets should require requests to use Secure Socket Layer, set to deny HTTP requests)
def cis_2_1_2(event, target_session, region, target_account_id, sns_topic_arn, bucket_name):

    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")
    
    # --- REMEDIATION CODE ---
    s3_client = target_session.client('s3')

    # Append HTTP deny policy to existing policy
    try:
        response = s3_client.get_bucket_policy(Bucket=bucket_name)
        existing_policy = json.loads(response['Policy'])
        
        http_deny_bucket_policy = [
            {
                'Sid': 'RequireSSL',
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 's3:*',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'Bool': {
                        'aws:SecureTransport': 'false'
                    }
                }
            }
        ]
        
        existing_policy['Statement'].extend(http_deny_bucket_policy)
        final_policy=json.dumps(existing_policy)
    
    # If error due to absence of any bucket policy
    except:
        
        http_deny_bucket_policy= {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'RequireSSL',
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 's3:*',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'Bool': {
                        'aws:SecureTransport': 'false'
                    }
                }
            }
        ]
        }
        
        final_policy=json.dumps(http_deny_bucket_policy)

    # Set the bucket policy
    s3_client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=final_policy
    )
    print("Bucket policy updated successfully.")

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - S3 Bucket Access Protocol Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
        
    Remediation Action Taken: {bucket_name} bucket policy has been updated."""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 2.1.3 (Ensure that MFA Delete is enabled on S3 buckets)
    # Automated Check is not supported by AWS SecurityHub


# CIS 2.1.4 (Ensure that all data in S3 buckets are discovered, classified and secured when required)
    # Automated Check is not supported by AWS SecurityHub


# CIS 2.1.5.1 (S3 Block Public Access setting should be enabled at account level)
def cis_2_1_5_1(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")
    
    # --- REMEDIATION CODE ---
    s3_client = target_session.client('s3control')
    # Enable block public access for the S3 bucket
    s3_client.put_public_access_block(
        PublicAccessBlockConfiguration={ 
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
        },
        AccountId=target_account_id
    )
    print(f"Public access blocked for bucket at account level for {target_account_id}") 

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - S3 Bucket Public Access Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
        
    Remediation Action Taken: S3 bucket public access policy has been updated at account level for {target_account_id}"""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 2.1.5.2 (S3 Block Public Access setting should be enabled at bucket level)
def cis_2_1_5_2(event, target_session, region, target_account_id, sns_topic_arn, bucket_name):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")
    
    # --- REMEDIATION CODE ---
    s3_client = target_session.client('s3')
    # Enable block public access for the S3 bucket
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
        'BlockPublicAcls': True,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': True,
        'RestrictPublicBuckets': True
        }
    )
    print(f"Public access blocked for bucket: {bucket_name} in account: {target_account_id} (Region: {region})")

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - S3 Bucket Public Access Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
        
    Remediation Action Taken: {bucket_name} bucket public access policy has been updated."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 2.2.1 (EBS default encryption should be enabled)
def cis_2_2_1(event, target_session, region, target_account_id, sns_topic_arn):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']

    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")
    
    # --- REMEDIATION CODE ---
    ec2_client = target_session.client('ec2')
    
    # Enable EBS encryption by default
    try:
        response = ec2_client.enable_ebs_encryption_by_default()
        print(f"Default EBS encryption has been enabled in {region}")
    except Exception as e:
        print('Error enabling Amazon EBS encryption by default:', str(e))
        return
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Default EBS Encryption"
    message = f"""
     Your Organization Security Administrator has performed remediation for the below security compliancy failure.
     
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
        
    Remediation Action Taken: Default EBS Encryption enabled in {region} region"""
        
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 2.3.1 (RDS DB instances should have encryption at-rest enabled)
def cis_2_3_1(event, target_session, region, target_account_id, sns_topic_arn, rds_id):

    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    print("No Automated Remediation exists for this control ID. Sending Remediation steps to SNS Topic")

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - RDS Encryption Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Steps to perform remediation:
        1. Create a snapshot of RDS instance ID: {rds_id}
        2. Make a copy of the snapshot and encrypt it
        3. Restore DB Instance from the encrypted snapshot
        4. Change the name of the original DB Instance
        5. Change the name of the Restored DB Instance to the original DB Instance name
        6. Delete the original RDS Instance and snapshot
        
    Please note that this needs to performed during maintenance period"""
    
    email_notification(target_session, sns_topic_arn, subject, message)
    manual_update_securityhub_status(event, target_session)


# --------------------------------- LOGGING CONTROLS ---------------------------------


# CIS 3.1 (CloudTrail should be enabled and configured with at least one multi-Region trail that includes read and write management events)
def cis_3_1_10_11(event, target_session, region, target_account_id, sns_topic_arn, bucket_name, trail_name):

    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    cloudtrail_client = target_session.client('cloudtrail')

    def create_cloudtrail():
        s3_client = target_session.client('s3')
        
        # Create a new S3 bucket
        s3_client.create_bucket(Bucket=bucket_name)

        print(f"S3 bucket {bucket_name} created successfully!")

        # Add a bucket policy to allow CloudTrail to write logs
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{target_account_id}/*",
                    "Condition": {
                        "StringEquals": {
                            "s3:x-amz-acl": "bucket-owner-full-control"
                        }
                    }
                },
                {
                    "Sid": "AllowCloudTrailGet",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "cloudtrail.amazonaws.com"
                    },
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket_name}"
                }
            ]
        }
        # Apply the bucket policy
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
        print(f"Bucket policy added to {bucket_name}")
        
        # Create a new trail with desired configuration
        response = cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=True,
            IncludeGlobalServiceEvents=True,
            EnableLogFileValidation=True
            
        )
        print("Multi region Trail has been enabled with Object level Read and Write Access")

    response = cloudtrail_client.describe_trails()
    if len(response['trailList']) == 0:
        create_cloudtrail()
        return
    else:
        print("CloudTrail already exists")

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Enable Multi region Trail with Read & Write Access"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Remediation Action Taken: Multi region Trail '{trail_name}' has been enabled with Object level Read and Write Access"""
    
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 3.2 (CloudTrail log file validation should be enabled)
def cis_3_2(event, target_session, region, target_account_id, sns_topic_arn, trail_name):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    cloudtrail_client = target_session.client('cloudtrail')
    
    # Enable log validation for the trail
    cloudtrail_client.update_trail(Name=trail_name, EnableLogFileValidation=True)
    print(f"Log validation enabled for CloudTrail trail: {trail_name}")     
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable CloudTrail Log Validation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Log validation enabled for CloudTrail trail: {trail_name}"""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 3.3 (Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible)
def cis_3_3(event, target_session, region, target_account_id, sns_topic_arn, bucket_name):

    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    s3_client = target_session.client('s3')

    # Enable block public access for the S3 bucket
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration = {
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )
    print(f"Public access blocked for Cloud trail bucket: {bucket_name}")

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Disable Public Access to CloudTrail logs"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Remediation Action Taken: Public access blocked for Cloud trail bucket: {bucket_name}"""
    
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)
    

# CIS 3.4 (CloudTrail trails should be integrated with Amazon CloudWatch Logs)
def cis_3_4(event, target_session, region, target_account_id, sns_topic_arn, iam_rolename, trail_name):

    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    cloudtrail_client = target_session.client('cloudtrail')
    iam_client = target_session.client('iam')

    log_group_name = f'/aws/cloudtrial/{trail_name}'
    logs_client = target_session.client('logs')

    permission_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "logs:CreateLogStream",
            "Resource": "arn:aws:logs:*:*:log-group:*",
            "Effect": "Allow"
        },
        {
            "Action": "logs:PutLogEvents",
            "Resource": "arn:aws:logs:*:*:log-group:*:log-stream:*",
            "Effect": "Allow"
        }
    ]
    }

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    try:
        iam_client.get_role(RoleName=iam_rolename)
        print(f"IAM role '{iam_rolename}' already exists.")
    except iam_client.exceptions.NoSuchEntityException:
        # Role does not exist, create it
        response = iam_client.create_role(
            RoleName=iam_rolename,
            AssumeRolePolicyDocument=json.dumps(trust_policy)
        )

        # Attach the permission policy to the role
        iam_client.put_role_policy(
            RoleName=iam_rolename,
            PolicyName='PermissionPolicy',
            PolicyDocument=json.dumps(permission_policy)
        )
        print(f"IAM role '{iam_rolename}' created successfully.")

    response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)

    if len(response['logGroups']) == 0:
        # Log group does not exist, create it
        logs_client.create_log_group(logGroupName=log_group_name)
        print(f"Log group '{log_group_name}' created successfully.")
    else:
        print(f"Log group '{log_group_name}' already exists.")
    
    response = cloudtrail_client.update_trail(
        Name=trail_name,
        CloudWatchLogsLogGroupArn=f'arn:aws:logs:{region}:{target_account_id}:log-group:{log_group_name}:*',
        CloudWatchLogsRoleArn=f'arn:aws:iam::{target_account_id}:role/{iam_rolename}',
    )

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Integrate CloudTrail with CloudWatch logs"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Remediation Action Taken: CloudTrail{trail_name} has been integrated with CloudWatch {log_group_name}."""
    
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)
    

# CIS 3.5 (AWS Config should be enabled)
    # No automatic remediation exists in the suggested environment setup
    # This compliancy will fail when we disable config control checks in some regions for Global resources


# CIS 3.6 (Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket)
def cis_3_6(event, target_session, region, target_account_id, sns_topic_arn, bucket_name):

    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    s3_client = target_session.client('s3')
    try:
        # Enable access logging for the S3 bucket
        logging_config = {
            'LoggingEnabled': {
                'TargetBucket': bucket_name,
                'TargetPrefix': 'accesslogs/'
            }
        }
        
        s3_client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus=logging_config)
        
        print(f"Access logging enabled for S3 bucket '{bucket_name}'")
    
    except Exception as e:
        print(f"Error: {str(e)}")
    
    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Setup Access logging in CloudTrail S3 Bucket"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Remediation Action Taken: Access logging has been enabled for CloudTrail bucket {bucket_name}."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)
    

# CIS 3.7 (CloudTrail Logs should have encryption at-rest enabled)
    # Pre-requisite: This function will execute successfully only upon deploying CloudFormation Template for "CIS_CloudTrail_Encryption_KMS_Key_Deployment"
def cis_3_7(event, target_session, region, target_account_id, sns_topic_arn, trail_name, key_alias):
   
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    cloudtrail_client = target_session.client('cloudtrail')
    
    cloudtrail_client.update_trail(
        Name=trail_name,
        KmsKeyId=f"arn:aws:kms:{region}:{target_account_id}:alias/{key_alias}" # Key created with CloudFormation template
    )

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Encrypt CloudTrail Logs at rest"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Remediation Action Taken: CloudTrail {trail_name} has been encrypted"""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 3.8 (AWS KMS key rotation should be enabled)
def cis_3_8(event, target_session, region, target_account_id, sns_topic_arn, exclusion_keywords, keyId):

    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---    
    kms_client = target_session.client('kms')
       
    try:
        keyDescription = kms_client.describe_key(KeyId=keyId)
        # Check if user-given keywords are in key description to avoid key rotation
        for keyword in exclusion_keywords:
            if (keyword not in str(keyDescription['KeyMetadata']['Description'])):
                rotationStatus = kms_client.get_key_rotation_status(KeyId=keyId)
                if rotationStatus['KeyRotationEnabled'] is False:               
                    response = kms_client.enable_key_rotation(KeyId=keyId)
                    if(response['ResponseMetadata']['HTTPStatusCode']==200):
                        print(f"\nSuccessfully Automatically rotate KMS key every year is enabled for key:{keyId}")
                    else :
                        print(response) 
    except:
        print(f"\nError Enabling Automatically KMS Key rotation for {keyId}")

    # --- SNS EMAIL INFO --- 
    subject = "CIS Control Remediation - Enable KMS Key Rotation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.

    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}

    Remediation Action Taken: Enabled Automatically rotate KMS key every year for key: {keyId}"""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 3.9 (Ensure VPC Flow logging is enabled in all VPCs)
def cis_3_9(event, target_session, region, target_account_id, sns_topic_arn, iam_role_name, vpc_id):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---    
    ec2_client = target_session.client('ec2')
    logs_client = target_session.client('logs')
    
    # Recheck if flow logs exist for the VPC
    flow_logs = ec2_client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])
    
    policy_arn = 'arn:aws:iam::aws:policy/CloudWatchFullAccess'
    
    def create_iam_role(role_name):
        iam_client = target_session.client('iam')
    
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "vpc-flow-logs.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
    
        try:
            iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
            print(f"Role {role_name} created successfully.")
        except iam_client.exceptions.EntityAlreadyExistsException:
            print(f"Role {role_name} already exists.")
    
        # Attach policy to the role
        try:
            iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )
            print(f"Policy {policy_arn} attached to role {role_name}.")
        except iam_client.exceptions.NoSuchEntityException:
            print(f"Role {role_name} or policy {policy_arn} does not exist.")

    
    # Create the IAM role if it does not exist
    create_iam_role(iam_role_name)
    
    # Check if VPC has flow logs enabled
    if flow_logs['FlowLogs'] == []:
        # Create log group if it doesn't exist
        log_group_name = f"/aws/vpc-flow-logs/{vpc_id}"
        try:
            logs_client.create_log_group(logGroupName=log_group_name)
        except:
            print('Specified Log group already exists.')
        
        # Enable flow logs for the VPC
        response = ec2_client.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType='VPC',
            TrafficType='REJECT',
            LogDestinationType='cloud-watch-logs',
            LogDestination=f'arn:aws:logs:{region}:{target_account_id}:log-group:{log_group_name}:*',
            DeliverLogsPermissionArn=f'arn:aws:iam::{target_account_id}:role/{iam_role_name}'
        )

        print(f"Flow logs enabled for VPC {vpc_id} in log group {log_group_name}")
    else:
        print(f"Flow logs already enabled for VPC {vpc_id}")
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable VPC Flowlogs"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Flow logs enabled for VPC {vpc_id}"""
    
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 3.10 (Ensure that object-level logging for write events is enabled for S3 buckets)
    # Control Check & Remediation is a part of CIS 3.1


# CIS 3.11 (Ensure that object-level logging for read events is enabled for S3 buckets)
    # Control Check & Remediation is a part of CIS 3.1



# --------------------------------- MONITORING CONTROLS ---------------------------------


# MONITORING CONTROL HELPER FUNCTIONS
def create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description,metric_name, namespace, threshold_value):
        cloudwatch_client = target_session.client('cloudwatch')

        # Check if Alarm already exists
        response = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
        alarms = response.get('MetricAlarms', [])
        for alarm in alarms:
            if alarm['AlarmName'] == alarm_name:
                print(f"CloudWatch alarm '{alarm_name}' already exists.")
                return

        # Create or update CloudWatch Alarm
        response = cloudwatch_client.put_metric_alarm(
            AlarmName=alarm_name,
            ComparisonOperator='GreaterThanOrEqualToThreshold',
            EvaluationPeriods=1,
            MetricName=metric_name,
            Namespace=namespace,
            Period=300,  # 5 minutes
            Statistic='Sum',
            Threshold=threshold_value,  # Minimum Threshold Value
            ActionsEnabled=True,  # True to trigger SNS action
            AlarmDescription=alarm_description,
            AlarmActions=[alarm_sns_topic],
            Dimensions=[]
        )
        print(f"Created CloudWatch alarm '{alarm_name}'.")

def create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace):
        logs_client = target_session.client('logs')

        # Check if Log Metric already exists
        response = logs_client.describe_metric_filters(logGroupName=log_group_name, filterNamePrefix=filter_name)
        filters = response.get('metricFilters', [])
        for filter in filters:
            if filter['filterName'] == filter_name:
                print(f"Log metric filter '{filter_name}' already exists in log group '{log_group_name}'.")
                return

        # Create or update log metric filter
        response = logs_client.put_metric_filter(
            logGroupName=log_group_name,
            filterName=filter_name,
            filterPattern=filter_pattern,
            metricTransformations=[
                {
                    'metricName': metric_name,
                    'metricNamespace': namespace,
                    'metricValue': '1',
                }
            ]
        )
        print(f"Created log metric filter '{filter_name}' in log group '{log_group_name}'.")


# CIS 4.1 (Ensure a log metric filter and alarm exist for Unauthorized API Calls)
    # Not exists in CISv1.4.0


# CIS 4.2 (Ensure a log metric filter and alarm exist for Management console sign-in without MFA)
    # Not exists in CISv1.4.0


# CIS 4.3 (Ensure a log metric filter and alarm exist for Usage of 'root' account)
def cis_4_3(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):

    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---  
    filter_pattern = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'

    # Important Variables
    filter_name = 'RootAccountUsageFilter'
    metric_name = 'RootAccountUsageLogMetric'
    namespace = 'RootAccountUsage'
    alarm_name = 'RootAccountUsageAlarm'
    alarm_description = 'Alarm to detect Root Account Usage'
    threshold_value = 1
    
    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source log group '{log_group_name}' does not exist.")
            return None
        else:
            raise

    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find Root Usage"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.4 (Ensure a log metric filter and alarm exist for IAM policy changes)
def cis_4_4(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}'

    # Important Variables
    filter_name = 'IAMPolicyChangesFilter'
    metric_name = 'IAMPolicyChangesLogMetric'
    namespace = 'IAMPolicyChanges'
    alarm_name = 'IAMPolicyChangesAlarm'
    alarm_description = 'Alarm to detect IAM Policy Changes'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
    
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find IAM Policy Change"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.5 (Ensure a log metric filter and alarm exist for CloudTrail configuration changes)
def cis_4_5(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'

    # Important Variables
    filter_name = 'CloudTrailConfigChangesFilter'
    metric_name = 'CloudTrailConfigChangesLogMetric'
    namespace = 'CloudTrailConfigChanges'
    alarm_name = 'CloudTrailConfigChangesAlarm'
    alarm_description = 'Alarm to detect CloudTrail Configuration Changes'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
    
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find CloudTrail Configuration Changes"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.6 (Ensure a log metric filter and alarm exist for AWS Management Console authentication failures)
def cis_4_6(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'

    # Important Variables
    filter_name = 'ConsoleAuthFailureFilter'
    metric_name = 'ConsoleAuthFailureLogMetric'
    namespace = 'ConsoleAuthFailure'
    alarm_name = 'ConsoleAuthFailureAlarm'
    alarm_description = 'Alarm to detect Console Authentication Failure'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find Console Authentication Failure"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.7 (Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs)
def cis_4_7(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    filter_pattern = '{ $.eventSource = kms* && $.errorMessage = "* is pending deletion."}'

    # Important Variables
    filter_name = 'CMKDisablingDeletionFilter'
    metric_name = 'CMKDisablingDeletionLogMetric'
    namespace = 'CMKDisablingDeletion'
    alarm_name = 'CMKDisablingDeletionAlarm'
    alarm_description = 'Alarm to detect Disabling/Deletion of Customer managed keys'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find Disabling/Deletion of CMKs"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.8 (Ensure a log metric filter and alarm exist for S3 bucket policy changes)
def cis_4_8(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'

    # Important Variables
    filter_name = 'S3BucketPolicyChangesFilter'
    metric_name = 'S3BucketPolicyChangesLogMetric'
    namespace = 'S3BucketPolicyChanges'
    alarm_name = 'S3BucketPolicyChangesAlarm'
    alarm_description = 'Alarm to detect S3 Bucket Policy Changes'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find S3 Bucket Policy Changes"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.9 (Ensure a log metric filter and alarm exist for AWS Config configuration changes)
def cis_4_9(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder)||($.eventName = DeleteDeliveryChannel)||($.eventName = PutDeliveryChannel)||($.eventName = PutConfigurationRecorder)) }'

    # Important Variables
    filter_name = 'AWSConfigChangesFilter'
    metric_name = 'AWSConfigChangesLogMetric'
    namespace = 'AWSConfigChangesChanges'
    alarm_name = 'AWSConfigChangesChangesAlarm'
    alarm_description = 'Alarm to detect AWS Config Configuration Changes'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find AWS Config configuration changes"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.10 (Ensure a log metric filter and alarm exist for Security Group changes)
def cis_4_10(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'

    # Important Variables
    filter_name = 'SecurityGroupChangesFilter'
    metric_name = 'SecurityGroupChangesLogMetric'
    namespace = 'SecurityGroupChanges'
    alarm_name = 'SecurityGroupChangesAlarm'
    alarm_description = 'Alarm to detect Security Group Changes'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find Security Group Changes"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.11 (Ensure a log metric filter and alarm exist for changes to Network Access Control Lists)
def cis_4_11(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'

    # Important Variables
    filter_name = 'NACLChangesFilter'
    metric_name = 'NetworkACLChangesLogMetric'
    namespace = 'NetworkACLChanges'
    alarm_name = 'NetworkACLChangesAlarm'
    alarm_description = 'Alarm to detect Network ACL Changes'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find Network ACL Changes"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.12 (Ensure a log metric filter and alarm exist for changes to Network Gateways)
def cis_4_12(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'

    # Important Variables
    filter_name = 'NetworkGatewayChangesFilter'
    metric_name = 'NetworkGatewayChangesLogMetric'
    namespace = 'NetworkGatewayChanges'
    alarm_name = 'NetworkGatewayChangesAlarm'
    alarm_description = 'Alarm to detect Network Gateway Changes'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find Network Gateway Changes"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.13 (Ensure a log metric filter and alarm exist for Route Table changes)
def cis_4_13(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE --- 
    filter_pattern = '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'

    # Important Variables
    filter_name = 'RouteTableChangesFilter'
    metric_name = 'RouteTableChangesLogMetric'
    namespace = 'RouteTableChanges'
    alarm_name = 'RouteTableChangesAlarm'
    alarm_description = 'Alarm to detect Route Table Changes'
    threshold_value = 1

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find Route Table Changes"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.14 (Ensure a log metric filter and alarm exist for VPC changes)
def cis_4_14(event, target_session, region, target_account_id, sns_topic_arn, log_group_name, alarm_sns_topic, threshold_value):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    filter_pattern = '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'

    # Important Variables
    filter_name = 'VPCChangesFilter'
    metric_name = 'VPCChangesLogMetric'
    namespace = 'VPCChanges'
    alarm_name = 'VPCChangesAlarm'
    alarm_description = 'Alarm to detect VPC Changes'

    try:
        create_log_metric(target_session, filter_name, filter_pattern, log_group_name, metric_name, namespace)
        create_cloud_watch_alarm(target_session, alarm_name, alarm_sns_topic, alarm_description, metric_name, namespace, threshold_value)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Monitoring source Log group '{log_group_name}' does not exist.")
            return None
        else:
            raise
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Enable Alarm to find VPC Changes"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}.
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Created log metric filter '{filter_name}' in log group '{log_group_name}', and CloudWatch alarm '{alarm_name}' has been created."""

    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 4.15 (Ensure a log metric filter and alarm exist for AWS Organization changes)
        # Automated Check is not supported by AWS SecurityHub
    


# --------------------------------- NETWORKING CONTROLS ---------------------------------


# CIS 5.1 (Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389)
    # Note: This code will additionally delete rules that allow "AnySource-AnyPort-AnyProtocol" or "AnySource-AllPort-AnyProtocol"
def cis_5_1(event, target_session, region, target_account_id, sns_topic_arn, network_acl_id, associated_vpc):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    ec2_client = target_session.client('ec2')
    
    removed_nacl_entries = []
    
    def delete_nacl_entry(network_acl_id, entry):
        ec2_client.delete_network_acl_entry(
                    NetworkAclId=network_acl_id,
                    Egress=False,
                    RuleNumber=entry['RuleNumber']
                )
        output = f"Removed network ACL rule with RuleNumber {entry['RuleNumber']} from NetworkACL {network_acl_id} in VPC {associated_vpc}"
        print(output)
        return output
    
    # Get the network ACL rules
    response = ec2_client.describe_network_acls(NetworkAclIds=[network_acl_id])
    
    if 'NetworkAcls' in response:
        network_acl = response['NetworkAcls'][0]

        # Remove the inbound rules that allow access from 0.0.0.0/0 to ports 22, 3389, or any port except 80
        for entry in network_acl['Entries']:
            if entry.get('CidrBlock') == '0.0.0.0/0' and entry.get('RuleAction') == 'allow' and entry.get('Egress') is False:
                # if from port 22, 3389, Any, ALL
                if entry.get('PortRange') is None or entry['PortRange'].get('From') in [22, 3389, -1, 0]:
                    output = delete_nacl_entry(network_acl_id, entry)
                    removed_nacl_entries.append(output)
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Network ACL Inbound Rule Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: The following rules that violate the compliancy have been deleted.
    """
    
    for removed_entry in removed_nacl_entries:
        message += f'\n{removed_entry}'
       
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)


# CIS 5.2 (Security Groups should not allow ingress from 0.0.0.0/0 to port 22 or port 3389)
    # Not exists in CISv1.4.0
    # Remediation is covered under CIS 5.1


# CIS 5.3 (VPC default security groups should not allow inbound or outbound traffic)
def cis_5_3(event, target_session, region, target_account_id, sns_topic_arn, vpc_id):
    
    cis_control = event['detail']['findings'][0]['Title']
    control_desc = event['detail']['findings'][0]['Description']
    
    print(cis_control)
    print(f"Task to be implemented on {target_account_id} in {region}")

    # --- REMEDIATION CODE ---
    ec2_client = target_session.client('ec2')
    
    # Get the default security group ID for the specified VPC
    response = ec2_client.describe_security_groups(
        Filters=[
            {'Name': 'vpc-id', 'Values': [vpc_id]},
            {'Name': 'group-name', 'Values': ['default']}
        ]
    )
    
    if 'SecurityGroups' in response:
        security_group = response['SecurityGroups'][0]
        default_security_group_id = security_group['GroupId']
        
        # Revoke all inbound rules for the default security group
        ec2_client.revoke_security_group_ingress(GroupId=default_security_group_id, IpPermissions=security_group['IpPermissions'])
        
        # Revoke all outbound rules for the default security group
        ec2_client.revoke_security_group_egress(GroupId=default_security_group_id, IpPermissions=security_group['IpPermissionsEgress'])
        
        print(f"Inbound and outbound rules disabled for the default security group {default_security_group_id} for VPC {vpc_id}")
    else:
        print("Default security group not found.")
        
    # --- SNS EMAIL INFO ---
    subject = "CIS Control Remediation - Network ACL Inbound Rule Violation"
    message = f"""
    Your Organization Security Administrator has performed remediation for the below security compliancy failure.
    
    Control Topic: {cis_control}

    Description: {control_desc}
    
    Target Account: {target_account_id}
    Region: {region}
    
    Remediation Action Taken: Both Inbound and Outboud rules of the default security group {default_security_group_id} of VPC {vpc_id} have been deleted."""
    
    email_notification(target_session, sns_topic_arn, subject, message)
    auto_update_securityhub_status(event, target_session)
    

# CIS 5.4 (Ensure routing tables for VPC Peering are "least access")
    # Automated Check is not supported by AWS SecurityHub