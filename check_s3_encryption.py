
import boto3
from botocore.exceptions import ClientError

from common import finding


ENCRYPTION_NAMES = {
    "AES256": "AES256 (SSE-S3)",
    "aws:kms": "aws:kms (SSE-KMS)",
    "aws:kms:dsse": "aws:kms:dsse (DSSE-KMS)"
}


def check_bucket_encryption(s3, bucket_name):

    results = []

    try:
        response = s3.get_bucket_encryption(
            Bucket=bucket_name
        )

        rules = response.get(
            "ServerSideEncryptionConfiguration", {}
        ).get("Rules", [])

        if not rules:
            results.append(
                finding(
                    "S3-ENCRYPTION",
                    f"bucket/{bucket_name}",
                    "INFO",
                    "No default encryption rules returned by the API",
                    "Verify the bucket configuration and existing "
                    "object encryption separately."
                )
            )

            return results

        for index, rule in enumerate(rules, start=1):

            encryption = rule.get(
                "ApplyServerSideEncryptionByDefault", {}
            )

            algorithm = encryption.get(
                "SSEAlgorithm", "UNKNOWN"
            )

            algorithm_name = ENCRYPTION_NAMES.get(
                algorithm, f"Unrecognized algorithm: {algorithm}"
            )

            if algorithm == "AES256":

                recommendation = (
                    "SSE-S3 is configured for new uploads. "
                    "Review whether this meets your data requirements."
                )

            elif algorithm == "aws:kms":

                recommendation = (
                    "Review KMS key permissions, key policies "
                    "and rotation requirements."
                )

            else:

                recommendation = (
                    "Review the encryption algorithm and "
                    "key-management configuration."
                )

            results.append(
                finding(
                    "S3-ENCRYPTION",
                    f"bucket/{bucket_name}",
                    "INFO",
                    f"Default encryption rule {index}: "
                    f"{algorithm_name}",
                    recommendation
                )
            )

    except ClientError as e:

        error_code = e.response["Error"]["Code"]

        if error_code == "ServerSideEncryptionConfigurationNotFoundError":

            results.append(
                finding(
                    "S3-ENCRYPTION",
                    f"bucket/{bucket_name}",
                    "INFO",
                    "No explicit encryption configuration returned. "
                    "S3 applies SSE-S3 to new uploads by default.",
                    "Verify existing objects separately and consider "
                    "SSE-KMS if customer-managed key control is required."
                )
            )

        else:

            print(
                f"Could not inspect encryption for "
                f"{bucket_name}: {error_code}"
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
                    check_bucket_encryption(bucket_s3, name)
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
            "No encryption status records returned. "
            "Review any API errors above."
        )

