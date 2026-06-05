import boto3
from botocore.exceptions import ClientError

def get_secret(secret_name: str, region_name: str = "us-east-1"):
try:
    session = boto3.session.Session(region_name=region_name)
try:
    client = session.client(service_name="secretsmanager")
except Exception as e:
    print(f"An error occurred: {e}")
    print(f"An error occurred: {e}")
    region_name=region_name
)

get_secret_value_response = client.get_secret_value(
    SecretId=secret_name
)
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response["SecretString"]
    return secret
