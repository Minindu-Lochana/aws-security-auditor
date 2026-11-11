
import boto3
from botocore.exceptions import ClientError

from common import finding


def run():
    iam = boto3.client("iam")
    results = []

    try:
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():

            for user in page["Users"]:
                name = user["UserName"]

                try:
                    response = iam.list_mfa_devices(
                        UserName=name
                    )

                    if not response["MFADevices"]:
                        results.append(
                            finding(
                                "IAM-MFA",
                                f"user/{name}",
                                "HIGH",
                                "User has no MFA device",
                                "Enable MFA"
                            )
                        )

                except ClientError as e:
                    error_code = e.response["Error"]["Code"]

                    print(
                        f"Could not check user {name}: "
                        f"{error_code}"
                    )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        print(f"IAM check failed: {error_code}")

    return results


if __name__ == "__main__":
    for result in run():
        print(result)

