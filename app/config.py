from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_env: str = "development"
    host: str = "0.0.0.0"
    port: int = 8080
    database_url: str
    jwt_issuer: str = ""
    jwt_audience: str = ""
    jwt_jwks_url: str = ""
    require_auth: bool = False
    aws_region: str = "us-east-1"
    aws_role_arn: str = ""
    aws_kms_key_id: str = ""
    aws_s3_bucket: str = ""
    aws_s3_object_lock_required: bool = False
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_key_vault_url: str = ""
    azure_key_name: str = ""
    azure_storage_account_url: str = ""
    azure_storage_container: str = ""
    google_cloud_project: str = ""
    google_application_credentials: str = ""
    gcp_kms_key_name: str = ""
    gcs_bucket: str = ""
    proxy_upstream_allowlist: str = ""
    fail_closed: bool = True
    max_action_body_bytes: int = 1048576
    payment_provider: str = "disabled"

settings = Settings()
