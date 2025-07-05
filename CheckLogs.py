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

import re
import time
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError
from dateutil import parser

BACKOFF_RATE = 1.5


def validate_time_range(start_time: str, end_time: str) -> bool:
    """
    Validate that start_time is before end_time.

    Args:
        start_time (str): Start time string in ISO format
        end_time (str): End time string in ISO format

    Returns:
        bool: True if time range is valid, False otherwise
    """
    if start_time and end_time:
        try:
            start = parser.parse(start_time)
            end = parser.parse(end_time)
            return start < end
        except Exception as e:
            print(f"[ERROR] Invalid time format: {str(e)}")
            return False
    return True


class ErrorPattern:

    def __init__(self, pattern, articles, redacted_message_pattern=r"", redact=True):
        """
        Initialize an error pattern matcher for API Gateway logs.

        Args:
            pattern (str): Regex pattern to match error messages
            articles (list): List of knowledge base article URLs related to the error
            redacted_message_pattern (str, optional): Pattern for redacting sensitive info. Defaults to empty string
            redact (bool, optional): Whether to redact sensitive information. Defaults to True

        Note:
            Used to identify specific error patterns in API Gateway logs and
            provide relevant troubleshooting articles.
        """
        self._pattern = pattern
        self._articles = articles
        self.redact = redact
        self.redacted_message_pattern = redacted_message_pattern

    @property
    def pattern(self):
        return self._pattern

    @property
    def articles(self):
        return self._articles


ERRORS = [
    ErrorPattern(
        pattern=r"(.*[Nn]etwork error communicating with endpoint.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-network-endpoint-error"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Execution failed due to configuration error: Invalid endpoint address.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-invalid-endpoint-address"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Execution failed due to a timeout error.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-lambda-integration-errors"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Malformed Lambda proxy response.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-lambda-integration-errors"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Lambda invocation failed with status: 429.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-lambda-integration-errors"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r".*401 Unauthorized.*",
        articles=[
            "https://repost.aws/knowledge-center/api-gateway-cognito-401-unauthorized",
            "https://repost.aws/knowledge-center/api-gateway-401-error-lambda-authorizer",
        ],
        redact=True,
        redacted_message_pattern=r"(\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)).*(401 Unauthorized).*",
    ),
    ErrorPattern(
        pattern=r"(.*Missing Authentication Token.*)",
        articles=[
            "https://repost.aws/knowledge-center/api-gateway-authentication-token-errors",
            "https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden",
        ],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*not authorized to perform: execute-api:Invoke on resource.*)",
        articles=[
            "https://repost.aws/knowledge-center/api-gateway-403-error-lambda-authorizer",
            "https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden",
        ],
        redact=True,
        redacted_message_pattern=r"(\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)).*(not authorized to perform: execute-api:Invoke on resource).*",
    ),
    ErrorPattern(
        pattern=r"(.*not authorized to access this resource.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-403-error-lambda-authorizer"],
        redact=True,
        redacted_message_pattern=r"(\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)).*(not authorized to access this resource).*",
    ),
    ErrorPattern(
        pattern=r"(.*User: anonymous is not authorized to perform: execute-api:Invoke on resource.*)",
        articles=[
            "https://repost.aws/knowledge-center/api-gateway-403-error-lambda-authorizer",
            "https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden",
        ],
        redact=True,
        redacted_message_pattern=r"(\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)).*(not authorized to perform: execute-api:Invoke on resource).*",
    ),
    ErrorPattern(
        pattern=r"(.*User is not authorized to access this resource with an explicit deny.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden"],
        redact=True,
        redacted_message_pattern=r"(\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)).*(not authorized to perform: execute-api:Invoke on resource).*",
    ),
    ErrorPattern(
        pattern=r"(.*The security token included in the request is invalid.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Signature expired.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Invalid API Key identifier specified.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*The request signature we calculated does not match the signature you provided.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Forbidden.*)",
        articles=[
            "https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden",
            "https://repost.aws/knowledge-center/api-gateway-vpc-connections",
        ],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Authorization header requires.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden"],
        redact=True,
        redacted_message_pattern=r"(\([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\)).*(Authorization header requires).*",
    ),
    ErrorPattern(
        pattern=r"(.*Method completed with status: 502.*)",
        articles=["https://repost.aws/knowledge-center/malformed-502-api-gateway"],
        redact=False,
    ),
    ErrorPattern(
        pattern=r"(.*Execution failed due to configuration error.*)",
        articles=["https://repost.aws/knowledge-center/api-gateway-500-error-vpc"],
        redact=False,
    ),
]


def analyse_logs(query_logs, access_log_message):
    """
    Analyzes API Gateway logs for known error patterns and provides troubleshooting guidance.

    Args:
        query_logs (str): Log messages from API Gateway execution logs
        access_log_message (str): Additional access log messages to append

    Returns:
        str: Analysis result containing:
            - Found error message (if any)
            - Relevant troubleshooting articles
            - Access log messages (if provided)
            - "No errors found" message if no patterns match

    Note:
        Searches through predefined error patterns and returns the first match
        with corresponding troubleshooting articles.
    """
    if access_log_message:
        access_log_message = f"\n{access_log_message}"
    if query_logs:
        for error in ERRORS:
            found = re.search(error.pattern, query_logs)
            if found:
                log_line = query_logs[found.start() : found.end()]
                if error.redact:
                    to_redact = re.search(error.redacted_message_pattern, log_line)
                    log_line = (
                        " ".join([match for match in to_redact.groups()]) + " [sensitive information has been redacted]"
                    )
                articles = "\n- ".join(error.articles)
                return f"Found the following error:\n\nLog: {log_line}\n\nRecommended articles:\n{articles}{access_log_message}"
        return "No error were found in the log group during the time range provided."
    else:
        return "No log group was found for the API."


def log_insights_query(query, log_group, start_time, end_time, is_access_log_query):
    """
    Executes a CloudWatch Logs Insights query with exponential backoff retry.

    Args:
        query (str): CloudWatch Logs Insights query string
        log_group (str): Name of the log group to query
        start_time (int): Start time in Unix timestamp format
        end_time (int): End time in Unix timestamp format
        is_access_log_query (bool): Whether this is an access log query

    Returns:
        str: Query results joined as a single string, or None if log group not found

    Raises:
        SystemExit: If query fails with an unexpected error

    Note:
        - Uses exponential backoff for query polling
        - Handles ResourceNotFoundException differently for access logs
        - Joins multiple log lines with newlines
    """
    logs = boto3.client("logs")
    try:
        query_response = logs.start_query(
            logGroupName=log_group, startTime=start_time, endTime=end_time, queryString=query
        )
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            return None
        else:
            print(f"[ERROR] Failed to start CloudWatch Logs Insights query: {error_code} - {str(e)}")
            raise RuntimeError(f"CloudWatch Logs error: {error_code} - {str(e)}")
    query_id = query_response["queryId"]

    response = logs.get_query_results(queryId=query_id)
    wait = 1
    while response["status"] == "Running":
        time.sleep(wait)
        wait *= BACKOFF_RATE
        response = logs.get_query_results(queryId=query_id)

    if not is_access_log_query and response["status"] in ["Failed", "Timeout", "Cancelled", "Unknown"]:
        print(f"[ERROR] CloudWatch Log Insights query failed. Query status: {response['status']}")
        raise RuntimeError(f"CloudWatch Logs Insights query failed with status: {response['status']}")

    query_result = response["results"]
    return "\n".join([line[0]["value"] for line in query_result])


def check_logs(event: dict, _) -> dict:
    """
    Main handler for checking API Gateway logs for errors.

    Args:
        event (dict): Contains required parameters:
            - RestApiId (str): ID of the API Gateway
            - StageName (str): Stage name to check
            - StartTime (str, optional): Start time for log search
            - EndTime (str, optional): End time for log search
            - RequestId (str, optional): Specific request ID to search
            - AccessLogName (str, optional): Access log group name
        _ (dict): Lambda context object (not used)

    Returns:
        str: Analysis results containing:
            - Error messages found
            - Relevant troubleshooting articles
            - Access log error messages if applicable

    Note:
        - Handles both execution logs and access logs
        - Supports time range and specific request ID filtering
        - Defaults to last 15 minutes if no time range specified
    """
    api_id: str = event.get("RestApiId", "")
    stage = event.get("StageName", "")
    start_time = event.get("StartTime", "")
    if start_time:
        try:
            start_time = int(parser.parse(event["StartTime"]).timestamp())
        except Exception as e:
            print(f"[ERROR] Invalid StartTime format: {event['StartTime']} - {str(e)}")
            raise ValueError(f"Invalid StartTime format: {event['StartTime']}")
    else:
        start_time = int((datetime.now() - timedelta(minutes=15)).timestamp())

    end_time = event.get("EndTime", "")
    if end_time:
        try:
            end_time = int(parser.parse(end_time).timestamp())
        except Exception as e:
            print(f"[ERROR] Invalid EndTime format: {end_time} - {str(e)}")
            raise ValueError(f"Invalid EndTime format: {end_time}")
    else:
        end_time = int(datetime.now().timestamp())

    # Validate time range
    if not validate_time_range(event.get("StartTime", ""), event.get("EndTime", "")):
        print("[ERROR] StartTime must be before EndTime")
        raise ValueError("StartTime must be before EndTime")

    request_id = event.get("RequestId", "")
    access_logs_arn = event.get("AccessLogName", "")

    log_group = f"API-Gateway-Execution-Logs_{api_id}/{stage}"
    access_log_message = ""

    if access_logs_arn:
        access_log_group = access_logs_arn.split(":")[-1]
        # specifically looking for 5XX errors
        access_logs_query = 'fields @message | filter status like "5" | sort @timestamp desc'
        access_logs = log_insights_query(access_logs_query, access_log_group, start_time, end_time, True)
        if access_logs:
            access_log_message = "5XX errors found in access logs. Recommended article for review:\nhttps://repost.aws/knowledge-center/api-gateway-find-5xx-errors-cloudwatch"

    query = "fields @message | sort @timestamp desc"
    if request_id:
        query = (
            f'fields @message | parse @message "(*) *" as rid, msg | filter rid = "{request_id}" | sort @timestamp desc'
        )

    cw_logs = log_insights_query(query, log_group, start_time, end_time, False)
    return analyse_logs(cw_logs, access_log_message)