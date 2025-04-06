from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    gemini_api_key: str

    model_config = SettingsConfigDict(env_file=".env")


@lru_cache
def get_config():
    return Config()
