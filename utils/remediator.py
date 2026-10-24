import boto3
from colorama import Fore, Style

def remediate_finding(finding):
    """Executes automated remediation actions based on the finding type."""
    check_name = finding.get("check_name")
    resource = finding.get("resource")

    print(f"\n{Fore.YELLOW}[AUTO-REMEDIATION TRIGGERED]{Style.RESET_ALL} Attempting to fix: {check_name} on {resource}...")

    try:
        if check_name == "S3 Public Access" or check_name == "S3 Policy Public":
            s3_client = boto3.client('s3')

            s3_client.put_public_access_block(
                Bucket=resource,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Successfully enforced S3 Block Public Access on bucket: {resource}")
            return True

        elif check_name == "RDS Publicly Accessible":
            rds_client = boto3.client('rds')
            rds_client.modify_db_instance(
                DBInstanceIdentifier=resource,
                PubliclyAccessible=False,
                ApplyImmediately=True
            )
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL}Successfully modified RDS instance {resource} to private.")
            return True
        else:
            print(f"{Fore.RED}[SKIPPED]{Style.RESET_ALL} No automated remediation script available for check: {check_name}")
            return False
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Remediation failed for {resource}: {str(e)}")
        return False
