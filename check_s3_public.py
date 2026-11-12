
import boto3
from botocore.exceptions import ClientError

from common import finding


PAB_SETTINGS = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets"
]


def check_bucket(s3, bucket_name):
    results = []

    try:
        response = s3.get_public_access_block(
            Bucket=bucket_name
        )

        config = response["PublicAccessBlockConfiguration"]

        disabled_settings = [
            setting
            for setting in PAB_SETTINGS
            if config.get(setting) is False
        ]

        if disabled_settings:
            results.append(
                finding(
                    "S3-PUBLIC-ACCESS",
                    f"bucket/{bucket_name}",
                    "MEDIUM",
                    "Bucket-level Block Public Access settings disabled: "
                    + ", ".join(disabled_settings),
                    "Review the bucket requirements and enable all "
                    "four Block Public Access settings."
                )
            )

    except ClientError as e:

        error_code = e.response["Error"]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":

            results.append(
                finding(
                    "S3-PUBLIC-ACCESS",
                    f"bucket/{bucket_name}",
                    "MEDIUM",
                    "No bucket-level Block Public Access configuration found",
                    "Configure all four bucket-level Block Public Access "
                    "settings and verify account-level protection."
                )
            )

        else:
            print(
                f"Could not inspect bucket {bucket_name}: "
                f"{error_code}"
            )

    return results


def run():

    s3 = boto3.client("s3")
    results = []
    scanned = 0

    try:
        paginator = s3.get_paginator("list_buckets")

        for page in paginator.paginate(
            PaginationConfig={"PageSize": 1000}
        ):

            for bucket in page.get("Buckets", []):

                name = bucket["Name"]
                region = bucket.get("BucketRegion")

                bucket_s3 = (
                    boto3.client("s3", region_name=region)
                    if region else s3
                )

                scanned += 1

                results.extend(
                    check_bucket(bucket_s3, name)
                )

    except ClientError as e:

        error_code = e.response["Error"]["Code"]

        print(f"S3 bucket listing failed: {error_code}")

        return results

    print(f"S3 buckets scanned: {scanned}")

    if scanned == 0:
        print("No buckets returned for this AWS identity.")

    return results


if __name__ == "__main__":

    findings = run()

    if findings:
        for result in findings:
            print(result)
    else:
        print(
            "No bucket-level public access findings returned. "
            "Review any API errors above."
        )

