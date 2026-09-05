from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "API Sentinel"
    debug: bool = False
    database_url: str = "sqlite:///./api_sentinel.db"
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
