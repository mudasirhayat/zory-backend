import boto3
from botocore.exceptions import ClientError
import boto3

def get_secret(secret_name: str, region_name: str = "us-east-1"):
    session = boto3.session.Session(region_name=region_name)
client = session.client(
    service_name="secretsmanager",
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
