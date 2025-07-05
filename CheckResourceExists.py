# Copyright 2025 Amazon.com, Inc. and its affiliates. All Rights Reserved.
# SPDX-License-Identifier: LicenseRef-.amazon.com.-AmznSL-1.0
# Licensed under the Amazon Software License (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#    http://aws.amazon.com/asl/
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

import boto3
from botocore.exceptions import ClientError


def check_resource_exists(event: dict, _) -> dict:
    """
    Verifies if a resource path exists in the specified API Gateway REST API.

    Args:
        event (dict): Contains 'RestApiId' and 'ResourcePath' to check
        _ (dict): Lambda context object (not used)

    Returns:
        dict: Contains resource existence status, authorization status, and resource ID
              {
                  "ResourceExists": bool,
                  "Authorized": bool,
                  "ResourceId": str
              }
    """
    apigw = boto3.client("apigateway")
    exists = False
    authorized = True
    api_id = event.get("RestApiId", "")
    resource_path = event.get("ResourcePath", "")
    resource_id = ""

    if not api_id or not resource_path:
        return {"ResourceExists": exists, "Authorized": authorized, "ResourceId": resource_id}

    try:
        paginator = apigw.get_paginator("get_resources")
        page_iterator = paginator.paginate(restApiId=api_id)
        for page in page_iterator:
            for item in page["items"]:
                if item["path"] == resource_path:
                    exists = True
                    resource_id = item["id"]

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFoundException":
            print(f"[WARNING] API {api_id} was not found.")
            exists = False
        elif error_code == "UnauthorizedException":
            print(f"[WARNING] Not authorized to access resources for API {api_id}.")
            authorized = False
        else:
            print(f"[ERROR] Unexpected error when retrieving resources for API {api_id}: {error_code} - {str(e)}")
            raise RuntimeError(f"Unexpected API Gateway error: {error_code} - {str(e)}")

    return {"ResourceExists": exists, "Authorized": authorized, "ResourceId": resource_id}