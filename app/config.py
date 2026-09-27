from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    model_config=SettingsConfigDict(env_file='.env',extra='ignore',case_sensitive=False)
    app_env:str='production'; host:str='0.0.0.0'; port:int=8080
    database_url:str
    require_auth:bool=True
    api_keys:str=''
    api_secret_key:str='CHANGE_THIS_TO_A_LONG_RANDOM_SECRET'
    proxy_upstream_allowlist:str=''
    proxy_timeout_seconds:float=20.0
    max_action_body_bytes:int=1048576
    fail_closed:bool=True
    rate_limit_per_minute:int=120
    recovery_timeout_seconds:float=20.0
    shadow_scan_timeout_seconds:float=8.0
settings=Settings()
