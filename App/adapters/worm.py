from datetime import datetime, timezone, timedelta

class ImmutableVault:
    """Writes evidence to a real immutable-capable object store.
    Backend must be configured; no local fake vault is used."""
    def __init__(self, backend, bucket_or_container):
        if backend not in {"s3","azure_blob","gcs"}:
            raise ValueError("backend must be s3, azure_blob, or gcs")
        if not bucket_or_container:
            raise ValueError("immutable storage target is required")
        self.backend=backend; self.target=bucket_or_container

    def put(self, key, data, retention_days=365):
        if self.backend=="s3":
            import boto3
            c=boto3.client("s3")
            c.put_object(Bucket=self.target,Key=key,Body=data,
                         ObjectLockMode="COMPLIANCE",
                         ObjectLockRetainUntilDate=datetime.now(timezone.utc)+timedelta(days=retention_days))
            return {"backend":"s3","key":key,"immutable":True}
        if self.backend=="gcs":
            from google.cloud import storage
            client=storage.Client(); bucket=client.bucket(self.target)
            blob=bucket.blob(key); blob.upload_from_string(data)
            bucket.retention_period=retention_days*86400
            bucket.patch()
            blob.reload()
            return {"backend":"gcs","key":key,"retention_seconds":bucket.retention_period}
        from azure.storage.blob import BlobServiceClient
        from .azure import azure_credential
        account=self.target
        client=BlobServiceClient(account_url=account,credential=azure_credential())
        # Container-level immutability must be configured by deployment/IaC.
        raise RuntimeError("Azure Blob upload requires a preconfigured immutable container; configure it via IaC before enabling writes.")
