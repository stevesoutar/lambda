from sys import getsizeof
import logging
import json

import boto3
from botocore.exceptions import ClientError

s3 = boto3.resource("s3")
buckets = s3.buckets.all()

iam = boto3.client("iam")

logger = logging.getLogger("dis-aws-cross-account-s3-access")
logger.setLevel(logging.INFO)

def get_buckets(buckets, tag):
    ipaas_buckets = []

    for bucket in buckets:
        try:
            tag_set = s3.BucketTagging(bucket.name).tag_set
        except ClientError as error_client:
            logger.error("ClientError from botocore.exceptions raised when attempting s3.BucketTagging().tag_set")
            logger.error("Error: " + error_client)
            continue
        except Exception as error_exception:
            logger.error("General Exception caught")
            logger.error("Error: " + error_exception)
            continue

        for tag in tag_set:
            if tag["Key"] == "ipaas_transfer_enabled" and tag["Value"] == tag:
                ipaas_buckets.append(bucket.name)

    return ipaas_buckets


def generate_resource_list(buckets, objects=False):
    resource_list = []

    for item in buckets:
        if not objects:
            resource_list.append("arn:aws:s3:::" + ipaas_bucket)
        else:
            resource_list.append("arn:aws:s3:::" + ipaas_bucket + "/*")

    return resource_list

def generate_policy(buckets, objects=False):
    if not objects:
        resource_list = generate_resource_list(buckets)
        ipaas_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AccountBucketPermissions",
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutLifecycleConfiguration",
                            "s3:ListBucketMultipartUploads",
                            "s3:ListBucket",
                            "s3:GetLifecycleConfiguration",
                            "s3:GetBucketLocation",
                            "s3:PutLifecycleConfiguration",
                        ],
                        "Resource": resource_list,
                    },
                ],
            }

    else:
        resource_list = generate_resource_list(buckets, objects=True)
        ipaas_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AccountObjectPermissions",
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObjectAcl",
                            "s3:PutObject",
                            "s3:GetObjectVersionAcl",
                            "s3:GetObjectVersion",
                            "s3:GetObjectAcl",
                            "s3:GetObject",
                            "s3:DeleteObjectVersion",
                            "s3:DeleteObject",
                            "s3:AbortMultipartUpload",
                        ],
                        "Resource": resource_list,
                    },
                ],
            }

return ipaas_policy

def detach_role_policy(role_name, policy_arn):
    try:
        response = iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as error_client:
        logger.error("ClientError from botocore.exceptions raised when attempting s3.BucketTagging().tag_set")
        logger.error("Error: " + error_client)
        return 1
    except Exception as error_exception:
        logger.error("General Exception caught")
        logger.error("Error: " + error_exception)
        return 2

    return 0

def delete_policy(policy_arn):
    try:
        response = iam.list_policy_versions(PolicyArn=policy_arn)
        for policy_version in response["Versions"]:
            if policy_version["IsDefaultVersion"]:
                continue
            response = iam.delete_policy_version(
                PolicyArn=policy_arn, VersionId=policy_version["VersionId"]
            )
        response = iam.delete_policy(PolicyArn=policy_arn)
    except ClientError as error_client:
        logger.error("ClientError from botocore.exceptions raised when attempting s3.BucketTagging().tag_set")
        logger.error("Error: " + error_client)
        return 1
    except Exception as error_exception:
        logger.error("General Exception caught")
        logger.error("Error: " + error_exception)
        return 2

    return 0

def create_policy(name, policy, policy_arn):
    try:
        response = iam.create_policy(
            PolicyName="dis-managed-ipaas-write-policy",
            PolicyDocument=json.dumps(ipaas_write_policy),
            Description="Write bucket policy for ipaas managed by dis lambda",
            Tags=[
                {"Key": "Technical_Owner", "Value": "dis"},
                {"Key": "Charge_Code", "Value": "15445"},
            ],
        )
    except ClientError as error_client:
        logger.error("ClientError from botocore.exceptions raised when attempting s3.BucketTagging().tag_set")
        logger.error("Error: " + error_client)
        return 1
    except Exception as error_exception:
        logger.error("General Exception caught")
        logger.error("Error: " + error_exception)
        return 2

    return 0

def lambda_handler(event, context):

    resource = boto3.resource("iam")
    acc_id = boto3.client("sts").get_caller_identity().get("Account")
    write_buckets_policy_arn = "arn:aws:iam::" + acc_id + ":policy/dis-managed-ipaas-write-buckets-policy"
    write_objects_policy_arn = "arn:aws:iam::" + acc_id + ":policy/dis-managed-ipaas-write-objects-policy"
    read_buckets_policy_arn = "arn:aws:iam::" + acc_id + ":policy/dis-managed-ipaas-read-buckets-policy"
    read_objects_policy_arn = "arn:aws:iam::" + acc_id + ":policy/dis-managed-ipaas-read-objects-policy"
    role_name = "dis-s3-bucket-cross-account-access"
    role = resource.Role(role_name)


    ipaas_write_buckets = get_buckets(buckets, "write")
    ipaas_write_buckets_policy = generate_policy(ipaas_write_buckets)
    ipaas_write_objects_policy = generate_policy(ipaas_write_buckets, objects=True)

    ipaas_read_buckets = get_buckets(buckets, "read")
    ipaas_read_buckets_policy = generate_policy(ipaas_read_buckets)
    ipaas_read_objects_policy = generate_policy(ipaas_read_buckets, objects=True)


    detach_role_policy(role_name, write_buckets_policy_arn)
    detach_role_policy(role_name, write_objects_policy_arn)
    delete_policy(write_buckets_policy_arn)
    delete_policy(write_objects_policy_arn)
    create_policy("dis-managed-ipaas-write-buckets-policy", ipaas_write_buckets_policy, write_buckets_policy_arn) 
    create_policy("dis-managed-ipaas-write-buckets-policy", ipaas_write_objects_policy, write_objects_policy_arn)
    role.attach_policy(PolicyArn=write_buckets_policy_arn)
    role.attach_policy(PolicyArn=write_objects_policy_arn)

    detach_role_policy(role_name, read_buckets_policy_arn)
    detach_role_policy(role_name, read_objects_policy_arn)
    delete_policy(read_buckets_policy_arn)
    delete_policy(read_objects_policy_arn)
    create_policy("dis-managed-ipaas-read-buckets-policy", ipaas_read_buckets_policy, read_buckets_policy_arn) 
    create_policy("dis-managed-ipaas-read-buckets-policy", ipaas_read_objects_policy, read_objects_policy_arn)
    role.attach_policy(PolicyArn=read_buckets_policy_arn)
    role.attach_policy(PolicyArn=read_objects_policy_arn)