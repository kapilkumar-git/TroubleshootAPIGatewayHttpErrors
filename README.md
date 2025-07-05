# TroubleshootAPIGatewayHttpErrors

This is the code for the AWS SSM Automation Document. While this is not the entire document, it's the Python code which is invoked by the Document itself.

**Flow:**
- Checks if the stage exists in the API Gateway ID provided (Rest API).
- If the stage exists, checks if the resource exists.
- If the resource exists, checks if the method (HTTP) exists.
- Once all information has been verified, it passes to the `analyse_logs` method, which then checks logs using CloudWatch (using a Logs Insights query) and looks for errors in the logs.
- Once a pattern matches, it provides the Knowledge Center article link for the resolution steps.

**Document Link:**  
https://us-east-1.console.aws.amazon.com/systems-manager/documents/AWSSupport-TroubleshootAPIGatewayHttpErrors/description?region=us-east-1

**Disclaimer:**  
The code has been altered a bit after I