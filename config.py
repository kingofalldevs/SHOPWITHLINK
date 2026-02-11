import os

from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_PATH = os.path.join(BASE_DIR, "instance")

# Load .env from project root (directory containing this file)
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-change-in-production"
    INSTANCE_PATH = INSTANCE_PATH
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///" + os.path.join(INSTANCE_PATH, "shopwithlink.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY") or ""
    PAYSTACK_PUBLIC_KEY = os.environ.get("PAYSTACK_PUBLIC_KEY") or ""
    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY") or ""
    SENDGRID_FROM_EMAIL = os.environ.get("SENDGRID_FROM_EMAIL") or "noreply@example.com"
    SENDGRID_FROM_NAME = os.environ.get("SENDGRID_FROM_NAME") or "Shop With Link"
