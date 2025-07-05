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


def check_api_exists(event, _) -> dict:
    """
    Checks if an API Gateway REST API exists and is accessible.

    Args:
        event (dict): Contains RestApiId to check
        _ (dict): Lambda context object (not used)

    Returns:
        dict: Contains boolean flags for API existence and authorization status
              {
                  "ApiExists": bool,
                  "Authorized": bool
              }
    """
    apigw = boto3.client("apigateway")
    api_id = event.get("RestApiId", "")
    if not api_id:
        return {"ApiExists": False, "Authorized": True}

    try:
        response = apigw.get_rest_api(restApiId=api_id)
        if response.get("id") == api_id:
            return {"ApiExists": True, "Authorized": True}
        return {"ApiExists": False, "Authorized": True}

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NotFoundException":
            return {"ApiExists": False, "Authorized": True}
        elif error_code == "UnauthorizedException":
            return {"ApiExists": False, "Authorized": False}
        else:
            print(f"[ERROR] Unexpected error when checking API {api_id}: {error_code} - {str(e)}")
            raise RuntimeError(f"Unexpected API Gateway error: {error_code} - {str(e)}")