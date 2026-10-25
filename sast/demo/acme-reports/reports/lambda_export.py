"""AWS Lambda: export a report to S3 on request from API Gateway."""
import json
import os


def handler(event, context):
    body = json.loads(event["body"])
    bucket = body.get("bucket", "reports")
    os.system("aws s3 cp /tmp/report.csv s3://" + bucket + "/")
    return {"statusCode": 200}


def _local_test():
    handler({"body": json.dumps({"bucket": "dev-reports"})}, None)
