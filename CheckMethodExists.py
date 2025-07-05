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


def check_method_exists(event: dict, _) -> dict:
    """
    Verifies if an HTTP method exists for a specific resource in the API Gateway REST API.

    Args:
        event (dict): Contains required parameters:
            - RestApiId (str): ID of the API Gateway REST API
            - ResourceId (str): ID of the resource to check
            - HttpMethod (str): HTTP method to verify (GET, POST, PUT, etc.)
        _ (dict): Lambda context object (not used)

    Returns:
        dict: Contains method existence and authorization status
              {
                  "MethodExists": bool,
                  "Authorized": bool
              }
    """
    apigw = boto3.client("apigateway")
    exists: bool = False
    authorized: bool = True
    api_id: str = event.get("RestApiId", "")
    resource_id: str = event.get("ResourceId", "")
    http_method: str = event.get("HttpMethod", "")

    if not api_id or not resource_id or not http_method:
        return {"MethodExists": exists, "Authorized": authorized}

    try:
        response = apigw.get_method(restApiId=api_id, resourceId=resource_id, httpMethod=http_method)

        if response.get("httpMethod", "") == http_method:
            exists = True
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFoundException":
            print(f"[WARNING] Method {http_method} not found for resource {resource_id} in API {api_id}.")
            exists = False
        elif error_code == "UnauthorizedException":
            print(
                f"[WARNING] Not authorized to access method {http_method} for resource {resource_id} in API {api_id}."
            )
            authorized = False
        else:
            print(
                f"[ERROR] Unexpected error when retrieving method {http_method} for resource {resource_id} in API {api_id}: {error_code} - {str(e)}"
            )
            raise RuntimeError(f"Unexpected API Gateway error: {error_code} - {str(e)}")

    return {"MethodExists": exists, "Authorized": authorized}