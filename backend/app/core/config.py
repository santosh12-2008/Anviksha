import os
from pydantic import BaseModel

class Settings(BaseModel):
    APP_NAME: str = "Anviksha (अन्वीक्षा) - Cognitive Email Forensics Platform"
    API_V1_STR: str = "/api"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "59765753e7dc53327fae9ee7600dfa2485d5d0f7918e480df35e7a4bb9e31747")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    DATABASE_URL: str = "sqlite:///./forensics.db"
    SIMULATION_MODE: bool = False

    # Google OAuth & Gmail API configuration provided by user
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "575128269135-tmn6f4ivv9mqgj9aafd6ts6mgio6m155.apps.googleusercontent.com")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "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")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:5173/auth/google/callback")
    SESSION_SECRET: str = os.getenv("SESSION_SECRET", "59765753e7dc53327fae9ee7600dfa2485d5d0f7918e480df35e7a4bb9e31747")

settings = Settings()
