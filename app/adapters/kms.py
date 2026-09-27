import base64, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class KMSUnavailable(RuntimeError): pass

class AwsKMS:
    def __init__(self, key_id, region):
        import boto3
        if not key_id: raise KMSUnavailable("AWS_KMS_KEY_ID is not configured")
        self.client=boto3.client("kms",region_name=region); self.key_id=key_id
    def sign(self, message: bytes):
        r=self.client.sign(KeyId=self.key_id, Message=message, MessageType="RAW", SigningAlgorithm="RSASSA_PSS_SHA_256")
        return r["Signature"]

class AzureKeyVaultSigner:
    def __init__(self, vault_url, key_name):
        from azure.keyvault.keys import KeyClient
        from .azure import azure_credential
        if not vault_url or not key_name: raise KMSUnavailable("Azure Key Vault is not configured")
        self.client=KeyClient(vault_url=vault_url,credential=azure_credential())
        self.key=self.client.get_key(key_name)
    def sign(self, message: bytes):
        import hashlib
        digest=hashlib.sha256(message).digest()
        return self.client.get_cryptography_client(self.key).sign("PS256",digest).signature

class GcpKMS:
    def __init__(self, key_name):
        from google.cloud import kms
        if not key_name: raise KMSUnavailable("GCP_KMS_KEY_NAME is not configured")
        self.client=kms.KeyManagementServiceClient(); self.key_name=key_name
    def sign(self, message: bytes):
        digest=hashlib.sha256(message).digest()
        r=self.client.asymmetric_sign(name=self.key_name,digest={"sha256":digest})
        return r.signature
