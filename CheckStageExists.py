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


def check_stage_exists(event: dict, _) -> dict:
    """
    Verifies if a stage exists in the specified API Gateway REST API and checks access logging configuration.

    Args:
        event (dict): Contains 'RestApiId' and 'StageName' to check
        _ (dict): Lambda context object (not used)

    Returns:
        dict: Contains stage existence status, authorization status, and CloudWatch log group
              {
                  "StageExists": bool,
                  "Authorized": bool,
                  "AccessLogGroup": str
              }
    """
    apigw = boto3.client("apigateway")
    exists: bool = False
    authorized: bool = True
    api_id: str = event.get("RestApiId", "")
    api_stage: str = event.get("StageName", "")
    access_log_group: str = ""

    if not api_id or not api_stage:
        return {"StageExists": False, "Authorized": authorized, "AccessLogGroup": access_log_group}
    else:
        try:
            response = apigw.get_stage(restApiId=api_id, stageName=api_stage)
            exists = "stageName" in response and response["stageName"] == api_stage
            if exists and "accessLogSettings" in response:
                access_log_group = response["accessLogSettings"]["destinationArn"]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NotFoundException":
                print(f"[WARNING] The API stage {api_stage} for API ID {api_id} was not found.")
                exists = False
            elif error_code == "UnauthorizedException":
                print(
                    "[WARNING] The IAM Role provided is not authorized to call apigateway:GetStage on the provided resource."
                )
                authorized = False
            else:
                print(
                    f"[ERROR] An issue occurred when attempting to retrieve the stage {api_stage} for API ID {api_id}\nError message: {str(e)}"
                )
                raise RuntimeError(f"Unexpected API Gateway error: {error_code} - {str(e)}")

    return {"StageExists": exists, "Authorized": authorized, "AccessLogGroup": access_log_group}