from azure.identity import DefaultAzureCredential
from .kms import KMSUnavailable

def azure_credential():
    return DefaultAzureCredential(exclude_interactive_browser_credential=True)
