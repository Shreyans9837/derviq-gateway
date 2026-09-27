from dataclasses import dataclass
from .kms import KMSUnavailable

@dataclass
class IntegrationStatus:
    provider: str
    configured: bool
    capability: str
    detail: str

def aws_status():
    try:
        import boto3
        sts=boto3.client("sts")
        ident=sts.get_caller_identity()
        return IntegrationStatus("aws",True,"sts_identity",ident.get("Arn",""))
    except Exception as e:
        return IntegrationStatus("aws",False,"sts_identity",f"NOT_CONFIGURED_OR_UNAVAILABLE:{type(e).__name__}")

def azure_status():
    from .azure import azure_credential
    try:
        cred=azure_credential()
        token=cred.get_token("https://management.azure.com/.default")
        return IntegrationStatus("azure",True,"managed_identity_or_service_principal",token.token[:8]+"...")
    except Exception as e:
        return IntegrationStatus("azure",False,"identity",f"NOT_CONFIGURED_OR_UNAVAILABLE:{type(e).__name__}")

def gcp_status():
    try:
        import google.auth
        creds, project=google.auth.default()
        return IntegrationStatus("gcp",True,"application_default_credentials",project or "")
    except Exception as e:
        return IntegrationStatus("gcp",False,"adc",f"NOT_CONFIGURED_OR_UNAVAILABLE:{type(e).__name__}")
