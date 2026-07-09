import sys
import boto3
from backend.database import SessionLocal
from backend import models
from backend.auth import decrypt_aws_credential
from backend.services.cspm_service import _check_vpc_flow_logs, _check_ebs_encryption, _check_guardduty, _check_kms_rotation, _check_rds_encryption, _check_iam_root, _check_s3_public_access

db = SessionLocal()
user = db.query(models.User).filter_by(id=7).first()
print("USER:", user.email, "KEY:", bool(user.aws_access_key_enc))

if user and user.aws_access_key_enc:
    key = decrypt_aws_credential(user.aws_access_key_enc)
    secret = decrypt_aws_credential(user.aws_secret_key_enc)
    session = boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret, region_name="us-east-1")
    try:
        print("S3 Public:", _check_s3_public_access(session, "us-east-1"))
        print("VPC Flow Logs:", _check_vpc_flow_logs(session, "us-east-1"))
        print("EBS Encryption:", _check_ebs_encryption(session, "us-east-1"))
        print("RDS Encryption:", _check_rds_encryption(session, "us-east-1"))
        print("KMS Rotation:", _check_kms_rotation(session, "us-east-1"))
        print("GuardDuty:", _check_guardduty(session, "us-east-1"))
        print("IAM Root:", _check_iam_root(session))
    except Exception as e:
        print("ERROR:", e)
else:
    print("No AWS creds")
