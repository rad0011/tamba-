# =====================================================
# TAMBA - PRODUCTION READY v14.0 (FULL MONOLITH)
# =====================================================

import os
import uuid
import asyncio
import hmac
import hashlib
import json
import logging
import random
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from decimal import Decimal, ROUND_DOWN
from typing import List, Optional, Dict, Any
from enum import Enum
from pathlib import Path
from contextlib import asynccontextmanager

import jwt
import redis.asyncio as redis
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request, UploadFile, File, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, field_validator, EmailStr, ConfigDict
from pydantic_settings import BaseSettings
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Numeric, ForeignKey, Text, JSON,
    Index, select, func, BigInteger, and_, UniqueConstraint
)
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from passlib.context import CryptContext
import phonenumbers
from phonenumbers import parse as parse_phone
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import httpx
from fastapi.staticfiles import StaticFiles
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.jobstores.memory import MemoryJobStore
import aiobreaker

# =====================================================
# CONFIGURATION
# =====================================================
class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite+aiosqlite:///./tamba.db"
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: str = ""
    REDIS_REQUIRED: bool = False
    JWT_SECRET: str = ""
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ENVIRONMENT: str = "production"
    DEBUG: bool = False
    PLATFORM_COMMISSION_RATE: Decimal = Decimal("0.03")
    PLATFORM_ACCOUNT_ID: str = "platform"

    ALLOWED_ORIGINS: str = "*"

    DEFAULT_ADMIN_EMAIL: str = "admin@tamba.com"
    DEFAULT_ADMIN_PASSWORD: str = "Admin123456!"
    DEFAULT_ADMIN_PHONE: str = "+221781234567"

    WAVE_API_KEY: str = "test"
    WAVE_API_SECRET: str = "test"
    WAVE_BASE_URL: str = "https://api.wave.com/v1"
    WAVE_WEBHOOK_SECRET: str = "test"
    WAVE_TIMEOUT: float = 30.0

    WAVE_CIRCUIT_FAILURE_THRESHOLD: int = 5
    WAVE_CIRCUIT_RECOVERY_TIMEOUT: int = 60

    TWILIO_ACCOUNT_SID: str = ""
    TWILIO_AUTH_TOKEN: str = ""
    TWILIO_PHONE_NUMBER: str = ""

    FIREBASE_CREDENTIALS_PATH: str = ""

    MAX_UPLOAD_SIZE: int = 5_242_880
    UPLOAD_DIR: str = "uploads"
    USE_S3: bool = False
    S3_BUCKET: str = ""
    S3_ACCESS_KEY: str = ""
    S3_SECRET_KEY: str = ""
    S3_REGION: str = "us-east-1"
    S3_ENDPOINT_URL: Optional[str] = None

    RATE_LIMIT_LOGIN: int = 5
    RATE_LIMIT_DEPOSIT: int = 10
    RATE_LIMIT_COTISER: int = 10
    RATE_LIMIT_WITHDRAW: int = 3
    RATE_LIMIT_OTP: int = 3
    RATE_LIMIT_TRANSFER: int = 5
    RATE_LIMIT_REGISTER: int = 3
    RATE_LIMIT_CREATE_TONTINE: int = 5
    RATE_LIMIT_INVITE: int = 20
    RATE_LIMIT_BUY: int = 20

    KYC0_DEPOSIT_LIMIT: Decimal = Decimal("50000")
    KYC0_WITHDRAW_LIMIT: Decimal = Decimal("25000")
    KYC1_DEPOSIT_LIMIT: Decimal = Decimal("200000")
    KYC1_WITHDRAW_LIMIT: Decimal = Decimal("100000")
    KYC2_DEPOSIT_LIMIT: Decimal = Decimal("1000000")
    KYC2_WITHDRAW_LIMIT: Decimal = Decimal("500000")

    OTP_EXPIRATION: int = 600

    model_config = ConfigDict(env_file=".env", extra="ignore")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.JWT_SECRET:
            self.JWT_SECRET = os.urandom(32).hex()
            logging.warning("JWT_SECRET generated randomly.")
        if self.ENVIRONMENT == "production" and not self.DEFAULT_ADMIN_PASSWORD:
            raise ValueError("DEFAULT_ADMIN_PASSWORD is required in production.")

    @property
    def allowed_origins_list(self) -> List[str]:
        if self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]

settings = Settings()

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("tamba")

# =====================================================
# DATABASE (SQLite)
# =====================================================
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()

# =====================================================
# REDIS (optionnel)
# =====================================================
redis_client = None

async def get_redis():
    global redis_client
    if not settings.REDIS_REQUIRED:
        return None
    if redis_client is None:
        try:
            redis_client = await redis.from_url(
                settings.REDIS_URL,
                password=settings.REDIS_PASSWORD if settings.REDIS_PASSWORD else None,
                decode_responses=True
            )
            await redis_client.ping()
            logger.info("Redis connected")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            redis_client = None
    return redis_client

async def redis_get(key: str) -> Optional[str]:
    r = await get_redis()
    if r:
        return await r.get(key)
    return None

async def redis_setex(key: str, seconds: int, value: str):
    r = await get_redis()
    if r:
        await r.setex(key, seconds, value)

async def redis_delete(key: str):
    r = await get_redis()
    if r:
        await r.delete(key)

async def redis_incr(key: str) -> int:
    r = await get_redis()
    if r:
        return await r.incr(key)
    return 1

async def redis_expire(key: str, seconds: int):
    r = await get_redis()
    if r:
        await r.expire(key, seconds)

async def redis_setnx(key: str, value: str, ttl: int = 30) -> bool:
    r = await get_redis()
    if r:
        result = await r.setnx(key, value)
        if result:
            await r.expire(key, ttl)
        return bool(result)
    return False

async def redis_del(key: str):
    r = await get_redis()
    if r:
        await r.delete(key)

# =====================================================
# ENUMS
# =====================================================
class Country(str, Enum):
    SN = "SN"

class Currency(str, Enum):
    XOF = "XOF"

class KycStatus(str, Enum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"

class KycLevel(str, Enum):
    KYC0 = "KYC0"
    KYC1 = "KYC1"
    KYC2 = "KYC2"

# =====================================================
# MODÈLES SQLAlchemy
# =====================================================
class UserDB(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    telephone = Column(String, unique=True, index=True, nullable=True)
    country = Column(String, default="SN")
    currency = Column(String, default="XOF")
    full_name = Column(String, nullable=True)
    solde = Column(Numeric(12, 2), default=Decimal("0.00"))
    epargne = Column(Numeric(12, 2), default=Decimal("0.00"))
    score = Column(Integer, default=100)
    nb_paiements = Column(Integer, default=0)
    nb_retards = Column(Integer, default=0)
    nb_achats = Column(Integer, default=0)
    nb_ventes = Column(Integer, default=0)
    bloque = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    kyc_status = Column(String, default=KycStatus.PENDING)
    kyc_level = Column(String, default=KycLevel.KYC0)
    kyc_verified_at = Column(DateTime, nullable=True)
    kyc_verified_by = Column(String, nullable=True)
    pin_hash = Column(String, nullable=True)
    version = Column(BigInteger, default=1)
    is_admin = Column(Boolean, default=False)
    lang = Column(String, default="fr")
    theme = Column(String, default="light")
    notify_sms = Column(Boolean, default=True)
    notify_push = Column(Boolean, default=True)
    is_temporary = Column(Boolean, default=False)

    transactions = relationship("TransactionDB", back_populates="user")
    produits_vendus = relationship("ProduitDB", back_populates="vendeur")
    membres_tontine = relationship("TontineMembreDB", back_populates="user")
    cotisations = relationship("CotisationDB", back_populates="user")
    notifications = relationship("NotificationDB", back_populates="user")
    messages = relationship("MessageDB", back_populates="user")
    ledger_entries = relationship("LedgerEntryDB", back_populates="user")
    device_tokens = relationship("DeviceTokenDB", back_populates="user")
    kyc_documents = relationship("KycDocumentDB", back_populates="user")
    otp_codes = relationship("OTPCodeDB", back_populates="user")


class OTPCodeDB(Base):
    __tablename__ = "otp_codes"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose = Column(String, nullable=False)
    code_hash = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("UserDB", back_populates="otp_codes")

    __table_args__ = (
        Index("ix_otp_user_purpose", "user_id", "purpose"),
    )


class TransactionDB(Base):
    __tablename__ = "transactions"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    montant = Column(Numeric(12, 2), nullable=False)
    currency = Column(String, nullable=False, default="XOF")
    type = Column(String, nullable=False)
    date = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    status = Column(String, default="pending", index=True)
    operator = Column(String, nullable=True)
    wave_transaction_id = Column(String, index=True, nullable=True)
    wave_request_id = Column(String, nullable=True)
    external_reference = Column(String, nullable=True, index=True)
    error_message = Column(String, nullable=True)
    produit_id = Column(String, ForeignKey("produits.id"), nullable=True)
    tontine_id = Column(String, ForeignKey("tontines.id"), nullable=True)
    cycle_id = Column(Integer, nullable=True)

    user = relationship("UserDB", back_populates="transactions")
    produit = relationship("ProduitDB")

    __table_args__ = (
        Index("ix_tx_external_ref", "external_reference", unique=False),
    )


class LedgerEntryDB(Base):
    __tablename__ = "ledger_entries"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    amount = Column(Numeric(12, 2), nullable=False)
    balance_after = Column(Numeric(12, 2), nullable=False)
    reason = Column(String, nullable=False)
    reference = Column(String, index=True, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("UserDB", back_populates="ledger_entries")


class DeviceTokenDB(Base):
    __tablename__ = "device_tokens"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String, unique=True, nullable=False)
    platform = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("UserDB", back_populates="device_tokens")


class PaymentLogDB(Base):
    __tablename__ = "payment_logs"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    operator = Column(String, nullable=False)
    request = Column(JSON, nullable=False)
    response = Column(JSON, nullable=True)
    status_code = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class KycDocumentDB(Base):
    __tablename__ = "kyc_documents"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String, nullable=False)
    url = Column(String, nullable=False)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("UserDB", back_populates="kyc_documents")


class ProduitDB(Base):
    __tablename__ = "produits"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    vendeur_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    nom = Column(String, nullable=False)
    description = Column(String, nullable=True)
    prix = Column(Numeric(12, 2), nullable=False)
    currency = Column(String, nullable=False, default="XOF")
    stock = Column(Integer, default=1)
    image_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    version = Column(BigInteger, default=1)

    vendeur = relationship("UserDB", back_populates="produits_vendus")


class TontineDB(Base):
    __tablename__ = "tontines"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    nom = Column(String, nullable=False)
    description = Column(String, nullable=True)
    montant_cotisation = Column(Numeric(12, 2), nullable=False)
    currency = Column(String, nullable=False, default="XOF")
    frequence = Column(String, nullable=False)
    mode_tirage = Column(String, default="ordre_fixe")
    date_creation = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    statut = Column(String, default="active", index=True)
    admin_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    cycle_actuel = Column(Integer, default=1)
    beneficiaire_actuel_id = Column(String, ForeignKey("users.id"), nullable=True)
    montant_collecte_cycle = Column(Numeric(12, 2), default=Decimal("0.00"))
    quorum = Column(Integer, default=50)
    autoriser_penalites = Column(Boolean, default=False)
    commission_plateforme = Column(Numeric(12, 2), default=Decimal("0.03"))
    autoriser_sortie_anticipee = Column(Boolean, default=True)
    autoriser_retrait_partiel = Column(Boolean, default=True)
    version = Column(BigInteger, default=1)

    admin = relationship("UserDB", foreign_keys=[admin_id])
    membres = relationship("TontineMembreDB", back_populates="tontine")
    cotisations = relationship("CotisationDB", back_populates="tontine")
    tours = relationship("TourDB", back_populates="tontine")


class TontineMembreDB(Base):
    __tablename__ = "tontine_membres"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    tontine_id = Column(String, ForeignKey("tontines.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String, default="membre")
    statut = Column(String, default="invite")
    ordre = Column(Integer, nullable=True)
    date_inscription = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    montant_cotise_total = Column(Numeric(12, 2), default=Decimal("0.00"))
    derniere_cotisation = Column(DateTime, nullable=True)
    version = Column(BigInteger, default=1)

    tontine = relationship("TontineDB", back_populates="membres")
    user = relationship("UserDB", back_populates="membres_tontine")

    __table_args__ = (
        UniqueConstraint("tontine_id", "user_id", name="ix_tontine_membre_unique"),
    )


class CotisationDB(Base):
    __tablename__ = "cotisations"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    tontine_id = Column(String, ForeignKey("tontines.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    montant = Column(Numeric(12, 2), nullable=False)
    penalite = Column(Numeric(12, 2), default=Decimal("0.00"))
    cycle_id = Column(Integer, nullable=False, index=True)
    date = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    status = Column(String, default="pending")
    wave_transaction_id = Column(String, index=True, nullable=True)
    external_reference = Column(String, unique=True, nullable=True, index=True)

    tontine = relationship("TontineDB", back_populates="cotisations")
    user = relationship("UserDB", back_populates="cotisations")


class TourDB(Base):
    __tablename__ = "tours"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    tontine_id = Column(String, ForeignKey("tontines.id", ondelete="CASCADE"), nullable=False, index=True)
    numero_cycle = Column(Integer, nullable=False)
    beneficiaire_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    date_debut = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    date_fin = Column(DateTime, nullable=True)
    montant_percu = Column(Numeric(12, 2), default=Decimal("0.00"))
    status = Column(String, default="en_cours")
    commission_plateforme = Column(Numeric(12, 2), default=Decimal("0.00"))
    payout_wave_transaction_id = Column(String, nullable=True)

    tontine = relationship("TontineDB", back_populates="tours")
    beneficiaire = relationship("UserDB")


class NotificationDB(Base):
    __tablename__ = "notifications"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String, nullable=False)
    title = Column(String, nullable=True)
    content = Column(String, nullable=False)
    sent = Column(Boolean, default=False)
    sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("UserDB", back_populates="notifications")


class MessageDB(Base):
    __tablename__ = "messages"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    tontine_id = Column(String, ForeignKey("tontines.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    tontine = relationship("TontineDB")
    user = relationship("UserDB", back_populates="messages")


class HelpArticle(Base):
    __tablename__ = "help_articles"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    lang = Column(String, default="fr")
    category = Column(String, nullable=True)
    order = Column(Integer, default=0)


class ProcessedWebhook(Base):
    __tablename__ = "processed_webhooks"
    id = Column(String, primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    external_reference = Column(String, unique=True, nullable=False, index=True)
    processed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# =====================================================
# SCHÉMAS PYDANTIC
# =====================================================
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    telephone: str
    full_name: Optional[str] = None

    @field_validator("telephone")
    @classmethod
    def validate_phone(cls, v):
        try:
            parsed = parse_phone(v, None)
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            raise ValueError("Numéro de téléphone invalide")


class CompleteRegistrationRequest(BaseModel):
    telephone: str
    email: EmailStr
    password: str = Field(..., min_length=8)
    otp: str
    pin: str = Field(..., min_length=4, max_length=6)

    @field_validator("telephone")
    @classmethod
    def validate_phone(cls, v):
        try:
            parsed = parse_phone(v, None)
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            raise ValueError("Numéro de téléphone invalide")


class UserOut(BaseModel):
    id: str
    email: str
    telephone: Optional[str]
    full_name: Optional[str]
    country: str
    currency: str
    solde: Decimal
    epargne: Decimal
    score: int
    bloque: bool
    created_at: datetime
    kyc_status: KycStatus
    kyc_level: KycLevel
    has_pin: bool

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: str
    password: str


class TransactionOut(BaseModel):
    id: str
    montant: Decimal
    currency: str
    type: str
    date: datetime
    status: str
    operator: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class PaymentRequest(BaseModel):
    montant: Decimal

    @field_validator("montant")
    @classmethod
    def montant_positif(cls, v):
        if v <= 0:
            raise ValueError("Le montant doit être positif")
        return v.quantize(Decimal("0.01"))


class EpargneRequest(BaseModel):
    montant: Decimal

    @field_validator("montant")
    @classmethod
    def montant_positif(cls, v):
        if v <= 0:
            raise ValueError("Le montant doit être positif")
        return v.quantize(Decimal("0.01"))


class TontineCreate(BaseModel):
    nom: str
    description: Optional[str] = None
    montant_cotisation: Decimal
    frequence: str
    mode_tirage: str = "ordre_fixe"
    participants_telephones: List[str] = []
    quorum: int = 50

    @field_validator("montant_cotisation")
    @classmethod
    def montant_positif(cls, v):
        if v <= 0:
            raise ValueError("Le montant de cotisation doit être positif")
        return v.quantize(Decimal("0.01"))


class TontineUpdate(BaseModel):
    nom: Optional[str] = None
    description: Optional[str] = None
    quorum: Optional[int] = None
    autoriser_penalites: Optional[bool] = None
    statut: Optional[str] = None


class TontineOut(BaseModel):
    id: str
    nom: str
    description: Optional[str]
    montant_cotisation: Decimal
    currency: str
    frequence: str
    mode_tirage: str
    statut: str
    admin_id: str
    cycle_actuel: int
    beneficiaire_actuel_id: Optional[str]
    montant_collecte_cycle: Decimal
    quorum: int
    autoriser_penalites: bool
    autoriser_sortie_anticipee: bool
    autoriser_retrait_partiel: bool
    date_creation: datetime

    model_config = ConfigDict(from_attributes=True)


class TontineMembreOut(BaseModel):
    id: str
    user_id: str
    role: str
    statut: str
    ordre: Optional[int]
    montant_cotise_total: Decimal
    derniere_cotisation: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)


class CotisationOut(BaseModel):
    id: str
    user_id: str
    montant: Decimal
    penalite: Decimal
    cycle_id: int
    date: datetime
    status: str

    model_config = ConfigDict(from_attributes=True)


class NotificationOut(BaseModel):
    id: str
    type: str
    title: Optional[str]
    content: str
    sent: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InviteRequest(BaseModel):
    telephone: str

    @field_validator("telephone")
    @classmethod
    def validate_phone(cls, v):
        try:
            parsed = parse_phone(v, None)
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        except Exception:
            raise ValueError("Numéro de téléphone invalide")


class CotisationRequest(BaseModel):
    description: Optional[str] = "Cotisation tontine"


class RetraitRequest(BaseModel):
    montant: Decimal
    otp: str
    pin: str

    @field_validator("montant")
    @classmethod
    def montant_positif(cls, v):
        if v <= 0:
            raise ValueError("Le montant doit être positif")
        return v.quantize(Decimal("0.01"))


class TransferRequest(BaseModel):
    telephone: str
    montant: Decimal
    otp: str
    pin: str

    @field_validator("montant")
    @classmethod
    def montant_positif(cls, v):
        if v <= 0:
            raise ValueError("Le montant doit être positif")
        return v.quantize(Decimal("0.01"))


class UserSettingsUpdate(BaseModel):
    lang: Optional[str] = None
    theme: Optional[str] = None
    notify_sms: Optional[bool] = None
    notify_push: Optional[bool] = None


class MessageCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=2000)


class MessageOut(BaseModel):
    id: str
    user_id: str
    content: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class HelpArticleOut(BaseModel):
    id: str
    title: str
    content: str
    category: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class OtpSendRequest(BaseModel):
    purpose: str


class OtpVerifyRequest(BaseModel):
    purpose: str
    code: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8)
    otp_code: str
    pin: str


class DeviceTokenRequest(BaseModel):
    token: str
    platform: str


class PinSetRequest(BaseModel):
    pin: str = Field(..., min_length=4, max_length=6)
    otp: str


class PinVerifyRequest(BaseModel):
    pin: str


class ProduitCreate(BaseModel):
    nom: str
    description: Optional[str] = None
    prix: Decimal
    stock: int = 1
    image_url: Optional[str] = None

    @field_validator("prix")
    @classmethod
    def prix_positif(cls, v):
        if v <= 0:
            raise ValueError("Le prix doit être positif")
        return v.quantize(Decimal("0.01"))


class ProduitOut(BaseModel):
    id: str
    nom: str
    description: Optional[str]
    prix: Decimal
    currency: str
    stock: int
    image_url: Optional[str]
    vendeur_id: str

    model_config = ConfigDict(from_attributes=True)


class AdminUserUpdate(BaseModel):
    bloque: Optional[bool] = None
    kyc_status: Optional[KycStatus] = None
    kyc_level: Optional[KycLevel] = None
    is_admin: Optional[bool] = None


class KycApproveRequest(BaseModel):
    user_id: str
    level: KycLevel
    status: KycStatus


class EmailUpdateRequest(BaseModel):
    new_email: EmailStr
    otp: str
    pin: str


class AdminUsersQuery(BaseModel):
    skip: int = 0
    limit: int = 50
    blocked: Optional[bool] = None
    kyc_level: Optional[KycLevel] = None
    kyc_status: Optional[KycStatus] = None
    cursor_id: Optional[str] = None


# =====================================================
# AUTHENTIFICATION
# =====================================================
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
pin_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
otp_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

VALID_OTP_PURPOSES = frozenset([
    "withdraw", "password_change", "transfer",
    "pin", "email_change", "complete_registration"
])


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_pin_hash(plain: str, hashed: str) -> bool:
    return pin_context.verify(plain, hashed)


def get_pin_hash(pin: str) -> str:
    return pin_context.hash(pin)


def hash_otp(code: str) -> str:
    return otp_context.hash(code)


def verify_otp_hash(code: str, hashed: str) -> bool:
    return otp_context.verify(code, hashed)


def create_access_token(data: dict) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = data.copy()
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


async def verify_token(token: str, token_type: str) -> str:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != token_type:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Type de token invalide")
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token invalide")
        blacklisted = await redis_get(f"blacklist:{token}")
        if blacklisted:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token révoqué")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expiré")
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token invalide")


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> UserDB:
    token = credentials.credentials
    user_id = await verify_token(token, "access")
    user = await db.get(UserDB, user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Utilisateur non trouvé")
    if user.bloque:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte bloqué")
    return user


async def get_current_admin(
    current_user: UserDB = Depends(get_current_user),
) -> UserDB:
    if not current_user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès administrateur requis")
    return current_user


def user_to_out(user: UserDB) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        telephone=user.telephone,
        full_name=user.full_name,
        country=user.country,
        currency=user.currency,
        solde=user.solde,
        epargne=user.epargne,
        score=user.score,
        bloque=user.bloque,
        created_at=user.created_at,
        kyc_status=user.kyc_status,
        kyc_level=user.kyc_level,
        has_pin=user.pin_hash is not None
    )


# =====================================================
# SERVICES EXTERNES
# =====================================================
class SMSService:
    @staticmethod
    async def send_sms(phone: str, message: str):
        if settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN:
            try:
                from twilio.rest import Client
                client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
                client.messages.create(
                    body=message,
                    from_=settings.TWILIO_PHONE_NUMBER,
                    to=phone
                )
                logger.info(f"SMS envoyé à {phone}")
            except Exception as e:
                logger.error(f"Erreur envoi SMS à {phone}: {e}")
        else:
            logger.info(f"[SIMULATION SMS] à {phone}: {message}")


class PushNotificationService:
    _initialized = False
    _fcm_app = None

    @classmethod
    async def initialize(cls):
        if cls._initialized:
            return
        if settings.FIREBASE_CREDENTIALS_PATH and os.path.exists(settings.FIREBASE_CREDENTIALS_PATH):
            try:
                import firebase_admin
                from firebase_admin import credentials
                cred = credentials.Certificate(settings.FIREBASE_CREDENTIALS_PATH)
                cls._fcm_app = firebase_admin.initialize_app(cred)
                cls._initialized = True
                logger.info("Firebase initialisé")
            except Exception as e:
                logger.error(f"Erreur init Firebase: {e}")
        else:
            logger.warning("Firebase non configuré — notifications push désactivées")

    @classmethod
    async def send_push(cls, token: str, title: str, body: str, data: dict = None):
        if not cls._initialized:
            return
        try:
            from firebase_admin import messaging
            message = messaging.Message(
                notification=messaging.Notification(title=title, body=body),
                data=data or {},
                token=token,
            )
            response = messaging.send(message)
            logger.info(f"Push envoyé: {response}")
        except Exception as e:
            logger.error(f"Erreur push: {e}")


class StorageService:
    @staticmethod
    async def upload_file(file: UploadFile, filename: str) -> str:
        if settings.USE_S3:
            try:
                import aioboto3
                session = aioboto3.Session()
                async with session.client(
                    's3',
                    endpoint_url=settings.S3_ENDPOINT_URL,
                    aws_access_key_id=settings.S3_ACCESS_KEY,
                    aws_secret_access_key=settings.S3_SECRET_KEY,
                    region_name=settings.S3_REGION
                ) as s3:
                    content = await file.read()
                    await s3.put_object(
                        Bucket=settings.S3_BUCKET,
                        Key=filename,
                        Body=content,
                        ContentType=file.content_type
                    )
                    if settings.S3_ENDPOINT_URL:
                        return f"{settings.S3_ENDPOINT_URL}/{settings.S3_BUCKET}/{filename}"
                    return f"https://{settings.S3_BUCKET}.s3.{settings.S3_REGION}.amazonaws.com/{filename}"
            except Exception as e:
                logger.error(f"Erreur upload S3: {e}")
                raise HTTPException(500, "Erreur lors de l'upload du fichier")
        else:
            # Création du dossier si inexistant (sécurité)
            os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
            filepath = Path(settings.UPLOAD_DIR) / filename
            content = await file.read()
            filepath.write_bytes(content)
            return f"/uploads/{filename}"


# Circuit breaker Wave
wave_circuit_breaker = aiobreaker.CircuitBreaker(
    fail_max=settings.WAVE_CIRCUIT_FAILURE_THRESHOLD,
    timeout_duration=settings.WAVE_CIRCUIT_RECOVERY_TIMEOUT
)


# =====================================================
# FONCTIONS MÉTIER CORE
# =====================================================
async def rate_limit_check(key: str, limit: int, period: int = 60, request: Request = None):
    if request is None:
        return
    client_ip = request.client.host if request.client else "unknown"
    full_key = f"rl:{key}:{client_ip}"
    current = await redis_incr(full_key)
    if current == 1:
        await redis_expire(full_key, period)
    if current > limit:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Trop de requêtes. Limite: {limit} par {period}s."
        )


async def add_ledger_entry(
    user_id: str,
    amount: Decimal,
    balance_after: Decimal,
    reason: str,
    reference: Optional[str],
    db: AsyncSession
):
    entry = LedgerEntryDB(
        user_id=user_id,
        amount=amount,
        balance_after=balance_after,
        reason=reason,
        reference=reference
    )
    db.add(entry)


async def check_kyc_limits(user: UserDB, amount: Decimal, operation: str):
    effective_level = user.kyc_level
    if user.kyc_status != KycStatus.VERIFIED and effective_level != KycLevel.KYC0:
        effective_level = KycLevel.KYC0

    deposit_limits = {
        KycLevel.KYC0: settings.KYC0_DEPOSIT_LIMIT,
        KycLevel.KYC1: settings.KYC1_DEPOSIT_LIMIT,
        KycLevel.KYC2: settings.KYC2_DEPOSIT_LIMIT,
    }
    withdraw_limits = {
        KycLevel.KYC0: settings.KYC0_WITHDRAW_LIMIT,
        KycLevel.KYC1: settings.KYC1_WITHDRAW_LIMIT,
        KycLevel.KYC2: settings.KYC2_WITHDRAW_LIMIT,
    }

    limit = deposit_limits.get(effective_level, settings.KYC0_DEPOSIT_LIMIT) \
        if operation == "deposit" \
        else withdraw_limits.get(effective_level, settings.KYC0_WITHDRAW_LIMIT)

    if amount > limit:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"Votre niveau KYC ({effective_level}) ne permet pas de {operation} plus de {limit} FCFA"
        )


async def generate_and_send_otp(
    user_id: str,
    purpose: str,
    db: AsyncSession,
    phone: str,
    request: Request
):
    await rate_limit_check(f"otp_send:{user_id}:{purpose}", 3, 300, request=request)

    now = datetime.now(timezone.utc)
    old_otps_result = await db.execute(
        select(OTPCodeDB).where(
            OTPCodeDB.user_id == user_id,
            OTPCodeDB.purpose == purpose,
            OTPCodeDB.used == False,
            OTPCodeDB.expires_at > now
        )
    )
    for old_otp in old_otps_result.scalars().all():
        old_otp.used = True

    code = str(random.randint(100000, 999999))
    expires_at = now + timedelta(seconds=settings.OTP_EXPIRATION)

    otp = OTPCodeDB(
        user_id=user_id,
        purpose=purpose,
        code_hash=hash_otp(code),
        expires_at=expires_at
    )
    db.add(otp)
    await db.commit()

    await SMSService.send_sms(
        phone,
        f"Votre code Tamba pour {purpose}: {code}. Valable {settings.OTP_EXPIRATION // 60} min."
    )
    logger.info(f"OTP généré pour user={user_id} purpose={purpose}")


async def verify_otp(
    user_id: str,
    purpose: str,
    code: str,
    db: AsyncSession,
    request: Request
) -> bool:
    await rate_limit_check(f"otp_attempt:{user_id}:{purpose}", settings.RATE_LIMIT_OTP, 60, request=request)

    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(OTPCodeDB).where(
            OTPCodeDB.user_id == user_id,
            OTPCodeDB.purpose == purpose,
            OTPCodeDB.used == False,
            OTPCodeDB.expires_at > now
        ).order_by(OTPCodeDB.created_at.desc()).limit(5)
    )
    otps = result.scalars().all()

    for otp in otps:
        if verify_otp_hash(code, otp.code_hash):
            otp.used = True
            await db.commit()
            return True
    return False


async def verify_pin(user: UserDB, pin: str) -> bool:
    if not user.pin_hash:
        return False
    return verify_pin_hash(pin, user.pin_hash)


async def detect_fraude(user: UserDB, montant: Decimal, db: AsyncSession, request: Request):
    time_limit = datetime.now(timezone.utc) - timedelta(minutes=5)
    recent_count_result = await db.execute(
        select(func.count()).select_from(TransactionDB).where(
            TransactionDB.user_id == user.id,
            TransactionDB.date >= time_limit
        )
    )
    recent_count = recent_count_result.scalar() or 0
    if recent_count > 10:
        user.score = max(0, user.score - 5)
    if montant > Decimal("10000.00"):
        user.score = max(0, user.score - 10)
    if user.score < 30:
        user.bloque = True
        await db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte bloqué pour suspicion de fraude")


async def update_score(user: UserDB, action: str, db: AsyncSession):
    score_delta = {"paiement": 2, "achat": 1, "vente": 2}.get(action, 0)
    nb_field = {"paiement": "nb_paiements", "achat": "nb_achats", "vente": "nb_ventes"}.get(action)

    if nb_field:
        current_val = getattr(user, nb_field, 0)
        setattr(user, nb_field, current_val + 1)

    user.score = max(0, min(1000, user.score + score_delta))


async def transfer_to_savings(user: UserDB, montant: Decimal, db: AsyncSession):
    if montant <= 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Le montant doit être positif")

    async with db.begin_nested():
        stmt = select(UserDB).where(
            UserDB.id == user.id,
            UserDB.version == user.version
        ).with_for_update()
        result = await db.execute(stmt)
        locked_user = result.scalar_one_or_none()

        if not locked_user:
            raise HTTPException(status.HTTP_409_CONFLICT, "Conflit de version, veuillez réessayer")
        if locked_user.solde < montant:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Solde insuffisant")

        locked_user.solde -= montant
        locked_user.epargne += montant
        locked_user.version += 1

        transaction = TransactionDB(
            user_id=locked_user.id,
            montant=-montant,
            currency=locked_user.currency,
            type="epargne",
            status="success"
        )
        db.add(transaction)
        await add_ledger_entry(
            locked_user.id, -montant, locked_user.solde,
            "Transfert vers épargne", None, db
        )

    await db.commit()
    await db.refresh(user)


async def suggerer_produits(user: UserDB, db: AsyncSession) -> List[Dict]:
    cache_key = f"suggestions:{user.id}"
    cached = await redis_get(cache_key)
    if cached:
        return json.loads(cached)

    produits_result = await db.execute(
        select(ProduitDB).where(
            ProduitDB.prix <= user.solde,
            ProduitDB.currency == user.currency,
            ProduitDB.stock > 0
        ).order_by(ProduitDB.prix.desc()).limit(5)
    )
    suggestions = [
        {"id": p.id, "nom": p.nom, "prix": str(p.prix), "image_url": p.image_url}
        for p in produits_result.scalars().all()
    ]
    await redis_setex(cache_key, 300, json.dumps(suggestions))
    return suggestions


async def create_notification(
    user_id: str,
    type_: str,
    title: str,
    content: str,
    db: AsyncSession
):
    notification = NotificationDB(
        user_id=user_id, type=type_, title=title, content=content
    )
    db.add(notification)
    await db.flush()

    user = await db.get(UserDB, user_id)
    if user and user.notify_push:
        device_tokens_result = await db.execute(
            select(DeviceTokenDB).where(DeviceTokenDB.user_id == user_id)
        )
        for dt in device_tokens_result.scalars().all():
            asyncio.create_task(
                PushNotificationService.send_push(dt.token, title, content)
            )


async def get_or_create_user_by_telephone(
    telephone: str,
    db: AsyncSession
) -> UserDB:
    try:
        parsed = parse_phone(telephone, None)
        phone_e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except Exception:
        raise ValueError(f"Numéro de téléphone invalide: {telephone}")

    result = await db.execute(
        select(UserDB).where(UserDB.telephone == phone_e164).with_for_update()
    )
    user = result.scalar_one_or_none()

    if not user:
        temp_email = f"temp_{uuid.uuid4().hex}@tamba-temp.internal"
        user = UserDB(
            email=temp_email,
            hashed_password=get_password_hash(str(uuid.uuid4())),
            telephone=phone_e164,
            country="SN",
            currency="XOF",
            solde=Decimal("0.00"),
            epargne=Decimal("0.00"),
            score=100,
            is_temporary=True
        )
        db.add(user)
        await db.flush()

    return user


async def save_upload_file(
    upload_file: UploadFile,
    allowed_types: List[str] = None
) -> str:
    if allowed_types is None:
        allowed_types = ["image/jpeg", "image/png", "image/jpg"]

    if upload_file.size and upload_file.size > settings.MAX_UPLOAD_SIZE:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Fichier trop volumineux. Maximum {settings.MAX_UPLOAD_SIZE // (1024 * 1024)} MB"
        )
    if upload_file.content_type not in allowed_types:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Type de fichier non autorisé. Types acceptés: {', '.join(allowed_types)}"
        )

    ext_parts = upload_file.filename.rsplit(".", 1)
    ext = ext_parts[-1].lower() if len(ext_parts) > 1 else "jpg"
    if ext not in ["jpg", "jpeg", "png"]:
        ext = "jpg"

    filename = f"{uuid.uuid4().hex}.{ext}"
    return await StorageService.upload_file(upload_file, filename)


# =====================================================
# PAYMENT GATEWAY
# =====================================================
class PaymentGateway(ABC):
    @abstractmethod
    async def create_payment_request(
        self, amount: Decimal, phone: str, reference: str, description: str = ""
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def transfer(
        self, amount: Decimal, recipient_phone: str, reference: str, description: str = ""
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    def verify_webhook(self, payload: bytes, headers: Dict[str, str]) -> bool:
        pass


class WaveGateway(PaymentGateway):
    name = "wave"

    def __init__(self):
        self.api_key = settings.WAVE_API_KEY
        self.base_url = settings.WAVE_BASE_URL
        self.webhook_secret = settings.WAVE_WEBHOOK_SECRET
        self.client = httpx.AsyncClient(timeout=settings.WAVE_TIMEOUT)

    async def _call_with_circuit(self, func, *args, **kwargs):
        try:
            return await wave_circuit_breaker.call(func, *args, **kwargs)
        except aiobreaker.CircuitBreakerError:
            logger.error("Circuit breaker Wave ouvert")
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "Service de paiement temporairement indisponible. Réessayez dans quelques minutes."
            )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(httpx.HTTPStatusError)
    )
    async def create_payment_request(
        self, amount: Decimal, phone: str, reference: str, description: str = ""
    ):
        async def _create():
            payload = {
                "amount": str(amount),
                "currency": "XOF",
                "payer": {"phone": phone},
                "reference": reference,
                "description": description
            }
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Idempotency-Key": reference
            }
            try:
                response = await self.client.post(
                    f"{self.base_url}/payment-requests",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
            except httpx.TimeoutException:
                logger.error(f"Timeout Wave pour reference={reference}")
                raise HTTPException(
                    status.HTTP_504_GATEWAY_TIMEOUT,
                    "Le service de paiement ne répond pas. La transaction peut être en cours."
                )
            data = response.json()
            await self._log_payment(reference, "create_payment_request", payload, data, response.status_code)
            return {
                "request_id": data["id"],
                "status": data["status"],
                "checkout_url": data.get("checkout_url")
            }

        return await self._call_with_circuit(_create)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(httpx.HTTPStatusError)
    )
    async def transfer(
        self, amount: Decimal, recipient_phone: str, reference: str, description: str = ""
    ):
        async def _transfer():
            payload = {
                "amount": str(amount),
                "currency": "XOF",
                "recipient": {"phone": recipient_phone},
                "reference": reference,
                "description": description
            }
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Idempotency-Key": reference
            }
            try:
                response = await self.client.post(
                    f"{self.base_url}/transfers",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
            except httpx.TimeoutException:
                logger.error(f"Timeout Wave transfer pour reference={reference}")
                return {"transfer_id": None, "status": "timeout", "reference": reference}

            data = response.json()
            await self._log_payment(reference, "transfer", payload, data, response.status_code)
            return {"transfer_id": data["id"], "status": data["status"]}

        return await self._call_with_circuit(_transfer)

    def verify_webhook(self, payload: bytes, headers: Dict[str, str]) -> bool:
        if not self.webhook_secret:
            logger.warning("WAVE_WEBHOOK_SECRET non configuré — vérification webhook désactivée")
            return settings.ENVIRONMENT != "production"

        signature = headers.get("x-wave-signature") or headers.get("X-Wave-Signature")
        if not signature:
            return False
        computed = hmac.new(
            self.webhook_secret.encode("utf-8"),
            payload,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(computed, signature)

    async def _log_payment(
        self, reference: str, operation: str,
        request_data: dict, response_data: dict, status_code: int
    ):
        try:
            async with AsyncSessionLocal() as db:
                log = PaymentLogDB(
                    user_id=settings.PLATFORM_ACCOUNT_ID,
                    operator="wave",
                    request={"operation": operation, "reference": reference},
                    response={k: v for k, v in response_data.items() if k not in ("signature",)},
                    status_code=status_code
                )
                db.add(log)
                await db.commit()
        except Exception as e:
            logger.error(f"Erreur log paiement: {e}")


class PaymentGatewayFactory:
    @classmethod
    def get_gateway(cls, operator: str = "wave") -> PaymentGateway:
        if operator == "wave":
            return WaveGateway()
        raise ValueError(f"Opérateur non supporté: {operator}")


# =====================================================
# LOGIQUE TONTINE
# =====================================================
async def determiner_prochain_beneficiaire(
    tontine: TontineDB, db: AsyncSession
) -> Optional[str]:
    membres_result = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine.id,
            TontineMembreDB.statut == "actif"
        ).order_by(TontineMembreDB.ordre)
    )
    membres = membres_result.scalars().all()
    if not membres:
        return None
    if tontine.mode_tirage == "ordre_fixe":
        index = (tontine.cycle_actuel - 1) % len(membres)
        return membres[index].user_id
    else:
        return random.choice(membres).user_id


async def initialiser_tour(tontine: TontineDB, db: AsyncSession):
    beneficiaire_id = await determiner_prochain_beneficiaire(tontine, db)
    if not beneficiaire_id:
        return
    tour = TourDB(
        tontine_id=tontine.id,
        numero_cycle=tontine.cycle_actuel,
        beneficiaire_id=beneficiaire_id,
        date_debut=datetime.now(timezone.utc),
        status="en_cours"
    )
    db.add(tour)
    tontine.beneficiaire_actuel_id = beneficiaire_id


async def verifier_et_cloturer_cycle(tontine: TontineDB, db: AsyncSession):
    nb_membres_result = await db.execute(
        select(func.count()).select_from(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine.id,
            TontineMembreDB.statut == "actif"
        )
    )
    nb_membres_actifs = nb_membres_result.scalar() or 0
    if nb_membres_actifs == 0:
        return

    nb_cotisations_result = await db.execute(
        select(func.count()).select_from(CotisationDB).where(
            CotisationDB.tontine_id == tontine.id,
            CotisationDB.cycle_id == tontine.cycle_actuel,
            CotisationDB.status == "success"
        )
    )
    nb_cotisations = nb_cotisations_result.scalar() or 0
    pourcentage = (nb_cotisations / nb_membres_actifs) * 100

    if pourcentage >= tontine.quorum:
        tour_result = await db.execute(
            select(TourDB).where(
                TourDB.tontine_id == tontine.id,
                TourDB.numero_cycle == tontine.cycle_actuel
            )
        )
        tour = tour_result.scalar_one_or_none()
        if tour and tour.status == "en_cours":
            tour.status = "cloture"
            tour.date_fin = datetime.now(timezone.utc)
            tontine.cycle_actuel += 1
            tontine.montant_collecte_cycle = Decimal("0.00")
            await initialiser_tour(tontine, db)


async def envoyer_rappel_cotisation(tontine: TontineDB, db: AsyncSession):
    cotisants_result = await db.execute(
        select(CotisationDB.user_id).where(
            CotisationDB.tontine_id == tontine.id,
            CotisationDB.cycle_id == tontine.cycle_actuel,
            CotisationDB.status == "success"
        )
    )
    cotisants_ids = [row.user_id for row in cotisants_result]

    non_cotisants_result = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine.id,
            TontineMembreDB.statut == "actif",
            TontineMembreDB.user_id.not_in(cotisants_ids) if cotisants_ids else True
        )
    )
    for membre in non_cotisants_result.scalars().all():
        await create_notification(
            membre.user_id,
            "sms",
            "Rappel de cotisation",
            f"Bonjour, n'oubliez pas de cotiser pour la tontine {tontine.nom} "
            f"(cycle {tontine.cycle_actuel}). Merci.",
            db=db
        )


# =====================================================
# APPLICATION FASTAPI
# =====================================================
scheduler = AsyncIOScheduler(jobstores={"default": MemoryJobStore()})


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──
    await get_redis()
    await PushNotificationService.initialize()

    # Création des tables SQLite
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Tables de la base de données créées/vérifiées")

    # Compte plateforme et admin
    async with AsyncSessionLocal() as db:
        platform = await db.get(UserDB, settings.PLATFORM_ACCOUNT_ID)
        if not platform:
            platform = UserDB(
                id=settings.PLATFORM_ACCOUNT_ID,
                email="platform@tamba.internal",
                hashed_password=get_password_hash(str(uuid.uuid4())),
                full_name="Plateforme Tamba",
                is_admin=True,
                solde=Decimal("0.00"),
                epargne=Decimal("0.00"),
                score=1000,
            )
            db.add(platform)
            await db.commit()

        admin_count_result = await db.execute(
            select(func.count()).select_from(UserDB).where(
                UserDB.is_admin == True,
                UserDB.id != settings.PLATFORM_ACCOUNT_ID
            )
        )
        if admin_count_result.scalar() == 0:
            if not settings.DEFAULT_ADMIN_PASSWORD:
                logger.critical("DEFAULT_ADMIN_PASSWORD non défini.")
            else:
                default_admin = UserDB(
                    email=settings.DEFAULT_ADMIN_EMAIL,
                    hashed_password=get_password_hash(settings.DEFAULT_ADMIN_PASSWORD),
                    telephone=settings.DEFAULT_ADMIN_PHONE,
                    full_name="Administrateur",
                    is_admin=True,
                    solde=Decimal("0.00"),
                    epargne=Decimal("0.00"),
                    score=1000,
                )
                db.add(default_admin)
                await db.commit()
                logger.info(f"Compte admin créé: {settings.DEFAULT_ADMIN_EMAIL}")

        existing_help_result = await db.execute(select(HelpArticle).limit(1))
        if not existing_help_result.scalar_one_or_none():
            articles = [
                HelpArticle(
                    title="Comment créer une tontine ?",
                    content="Pour créer une tontine, allez dans l'onglet Tontines et cliquez sur 'Créer'.",
                    lang="fr", category="tontine", order=1
                ),
                HelpArticle(
                    title="Comment cotiser ?",
                    content="Ouvrez votre tontine et appuyez sur 'Cotiser'. Suivez les instructions de paiement.",
                    lang="fr", category="paiement", order=2
                ),
            ]
            db.add_all(articles)
            await db.commit()

    scheduler.add_job(scheduled_reminders, CronTrigger(hour=8, minute=0), id="reminders")
    scheduler.start()
    logger.info(f"Tamba v14.0 (SQLite) démarrée — ENV={settings.ENVIRONMENT}")

    yield

    # ── Shutdown ──
    scheduler.shutdown(wait=False)
    await engine.dispose()
    if redis_client:
        await redis_client.aclose()
    logger.info("Tamba arrêtée proprement")


app = FastAPI(
    title="Tamba API",
    version="14.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else "/docs",
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

# === CORRECTION : créer le dossier uploads avant de le monter ===
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=settings.UPLOAD_DIR), name="uploads")


async def scheduled_reminders():
    lock_key = "lock:scheduled_reminders"
    lock_value = str(uuid.uuid4())
    locked = await redis_setnx(lock_key, lock_value, ttl=300)
    if not locked:
        logger.info("Rappels déjà en cours sur une autre instance — skip")
        return

    try:
        async with AsyncSessionLocal() as db:
            tontines_result = await db.execute(
                select(TontineDB).where(TontineDB.statut == "active")
            )
            for tontine in tontines_result.scalars().all():
                await envoyer_rappel_cotisation(tontine, db)
            await db.commit()
        logger.info("Rappels de cotisation envoyés")
    except Exception as e:
        logger.error(f"Erreur dans scheduled_reminders: {e}")
    finally:
        await redis_del(lock_key)


# =====================================================
# ENDPOINTS AUTH
# =====================================================
@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"register:{user_data.email}", settings.RATE_LIMIT_REGISTER, 300, request)

    existing_email = await db.execute(select(UserDB).where(UserDB.email == user_data.email))
    if existing_email.scalar_one_or_none():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email déjà utilisé")

    existing_phone = await db.execute(select(UserDB).where(UserDB.telephone == user_data.telephone))
    if existing_phone.scalar_one_or_none():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Téléphone déjà utilisé")

    user = UserDB(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        telephone=user_data.telephone,
        full_name=user_data.full_name,
        country="SN",
        currency="XOF",
        solde=Decimal("0.00"),
        epargne=Decimal("0.00"),
        score=100,
        is_temporary=False
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user_to_out(user)


@app.post("/auth/complete", response_model=UserOut)
async def complete_registration(
    req: CompleteRegistrationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"complete:{req.telephone}", 3, 300, request)

    user_result = await db.execute(
        select(UserDB).where(
            UserDB.telephone == req.telephone,
            UserDB.is_temporary == True
        )
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Aucun compte temporaire trouvé pour ce numéro")

    if not await verify_otp(user.id, "complete_registration", req.otp, db, request):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP invalide ou expiré")

    existing_email = await db.execute(select(UserDB).where(UserDB.email == req.email))
    if existing_email.scalar_one_or_none():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email déjà utilisé")

    user.email = req.email
    user.hashed_password = get_password_hash(req.password)
    user.pin_hash = get_pin_hash(req.pin)
    user.is_temporary = False
    await db.commit()
    await db.refresh(user)
    return user_to_out(user)


@app.post("/auth/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"login:{login_data.email}", settings.RATE_LIMIT_LOGIN, 60, request)

    result = await db.execute(select(UserDB).where(UserDB.email == login_data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Identifiants invalides")

    if user.is_temporary:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Compte temporaire. Finalisez votre inscription via /auth/complete"
        )
    if user.bloque:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte bloqué")

    access_token = create_access_token({"sub": user.id})
    refresh_token = create_refresh_token({"sub": user.id})
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.post("/auth/refresh", response_model=Token)
async def refresh_token(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token manquant")
    token = auth.split(" ", 1)[1]
    user_id = await verify_token(token, "refresh")
    new_access = create_access_token({"sub": user_id})
    return {"access_token": new_access, "refresh_token": token, "token_type": "bearer"}


@app.post("/auth/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    expire_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    await redis_setex(f"blacklist:{token}", expire_seconds, "1")
    return {"ok": True}


# =====================================================
# ENDPOINTS UTILISATEUR
# =====================================================
@app.get("/users/me", response_model=UserOut)
async def get_me(current_user: UserDB = Depends(get_current_user)):
    return user_to_out(current_user)


@app.patch("/users/me/settings")
async def update_settings(
    settings_data: UserSettingsUpdate,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    for key, value in settings_data.model_dump(exclude_unset=True).items():
        setattr(current_user, key, value)
    await db.commit()
    return {"ok": True}


@app.post("/users/me/update-email")
async def update_email(
    req: EmailUpdateRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not await verify_otp(current_user.id, "email_change", req.otp, db, request):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Code OTP invalide")
    if not await verify_pin(current_user, req.pin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "PIN incorrect")

    existing = await db.execute(select(UserDB).where(UserDB.email == req.new_email))
    if existing.scalar_one_or_none():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email déjà utilisé")

    current_user.email = req.new_email
    await db.commit()
    return {"ok": True}


@app.post("/users/me/pin/set")
async def set_pin(
    req: PinSetRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not await verify_otp(current_user.id, "pin", req.otp, db, request):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Code OTP invalide ou expiré")
    current_user.pin_hash = get_pin_hash(req.pin)
    await db.commit()
    return {"ok": True, "message": "PIN enregistré avec succès"}


@app.post("/users/me/pin/verify")
async def verify_pin_endpoint(
    req: PinVerifyRequest,
    current_user: UserDB = Depends(get_current_user)
):
    if not await verify_pin(current_user, req.pin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "PIN incorrect")
    return {"ok": True}


@app.post("/users/me/otp/send")
async def send_otp(
    req: OtpSendRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if req.purpose not in VALID_OTP_PURPOSES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Purpose invalide. Valeurs acceptées: {', '.join(VALID_OTP_PURPOSES)}"
        )
    if not current_user.telephone:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Numéro de téléphone non défini sur ce compte")

    await generate_and_send_otp(current_user.id, req.purpose, db, current_user.telephone, request)
    return {"ok": True, "message": "Code OTP envoyé par SMS"}


@app.post("/users/me/verify-otp")
async def verify_otp_endpoint(
    req: OtpVerifyRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    valid = await verify_otp(current_user.id, req.purpose, req.code, db, request)
    if not valid:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Code OTP invalide ou expiré")
    return {"ok": True}


@app.post("/users/me/change-password")
async def change_password(
    req: ChangePasswordRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"change_password:{current_user.id}", 3, 300, request)

    if not verify_password(req.old_password, current_user.hashed_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Ancien mot de passe incorrect")
    if not await verify_otp(current_user.id, "password_change", req.otp_code, db, request):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Code OTP invalide")
    if not await verify_pin(current_user, req.pin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "PIN incorrect")

    current_user.hashed_password = get_password_hash(req.new_password)
    await db.commit()
    return {"ok": True}


@app.post("/users/me/deposit")
async def initiate_deposit(
    payment: PaymentRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.bloque:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte bloqué")

    await rate_limit_check(f"deposit:{current_user.id}", settings.RATE_LIMIT_DEPOSIT, 60, request)
    await check_kyc_limits(current_user, payment.montant, "deposit")
    await detect_fraude(current_user, payment.montant, db, request)

    if not current_user.telephone:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Numéro de téléphone requis pour le dépôt")

    gateway = PaymentGatewayFactory.get_gateway("wave")
    external_ref = f"deposit_{uuid.uuid4().hex}"

    try:
        wave_resp = await gateway.create_payment_request(
            amount=payment.montant,
            phone=current_user.telephone,
            reference=external_ref
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur Wave deposit: {e}")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Erreur lors de l'initiation du paiement")

    transaction = TransactionDB(
        user_id=current_user.id,
        montant=payment.montant,
        currency=current_user.currency,
        type="deposit",
        status="pending",
        operator=gateway.name,
        external_reference=external_ref,
        wave_request_id=wave_resp["request_id"]
    )
    db.add(transaction)
    await db.commit()
    return {"checkout_url": wave_resp["checkout_url"], "transaction_id": transaction.id}


@app.post("/users/me/save", response_model=UserOut)
async def save_money(
    epargne_data: EpargneRequest,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await transfer_to_savings(current_user, epargne_data.montant, db)
    await db.refresh(current_user)
    return user_to_out(current_user)


@app.get("/users/me/savings/stats")
async def get_savings_stats(current_user: UserDB = Depends(get_current_user)):
    return {
        "epargne": str(current_user.epargne),
        "solde": str(current_user.solde)
    }


@app.get("/users/me/transactions", response_model=List[TransactionOut])
async def get_transactions(
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 20,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
):
    limit = min(limit, 100)
    query = select(TransactionDB).where(TransactionDB.user_id == current_user.id)
    if start_date:
        query = query.where(TransactionDB.date >= start_date)
    if end_date:
        query = query.where(TransactionDB.date <= end_date)
    query = query.order_by(TransactionDB.date.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@app.get("/users/me/notifications", response_model=List[NotificationOut])
async def get_notifications(
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 20
):
    limit = min(limit, 100)
    result = await db.execute(
        select(NotificationDB)
        .where(NotificationDB.user_id == current_user.id)
        .order_by(NotificationDB.created_at.desc())
        .offset(skip).limit(limit)
    )
    return result.scalars().all()


@app.post("/users/me/withdraw")
async def withdraw(
    req: RetraitRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.bloque:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte bloqué")

    await rate_limit_check(f"withdraw:{current_user.id}", settings.RATE_LIMIT_WITHDRAW, 60, request)
    await check_kyc_limits(current_user, req.montant, "withdraw")

    if not await verify_otp(current_user.id, "withdraw", req.otp, db, request):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP invalide")
    if not await verify_pin(current_user, req.pin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "PIN incorrect")

    external_ref = f"withdraw_{uuid.uuid4().hex}"
    tx = None

    async with db.begin():
        stmt = select(UserDB).where(
            UserDB.id == current_user.id,
            UserDB.version == current_user.version
        ).with_for_update()
        locked_user = (await db.execute(stmt)).scalar_one_or_none()

        if not locked_user:
            raise HTTPException(status.HTTP_409_CONFLICT, "Conflit de version, réessayez")
        if locked_user.solde < req.montant:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Solde insuffisant")

        locked_user.solde -= req.montant
        locked_user.version += 1

        tx = TransactionDB(
            user_id=locked_user.id,
            montant=-req.montant,
            currency=locked_user.currency,
            type="withdraw",
            status="pending",
            operator="wave",
            external_reference=external_ref
        )
        db.add(tx)

    gateway = PaymentGatewayFactory.get_gateway("wave")
    try:
        transfer_resp = await gateway.transfer(
            amount=req.montant,
            recipient_phone=current_user.telephone,
            reference=external_ref,
            description="Retrait Tamba"
        )
        wave_status = transfer_resp.get("status")
    except HTTPException:
        wave_status = "failed"
    except Exception as e:
        logger.error(f"Erreur Wave withdraw: {e}")
        wave_status = "failed"

    async with db.begin():
        tx_fresh = await db.get(TransactionDB, tx.id, with_for_update=True)
        user_fresh = await db.get(UserDB, current_user.id, with_for_update=True)

        if wave_status in ("completed", "timeout"):
            tx_fresh.status = "success" if wave_status == "completed" else "pending_wave"
            tx_fresh.wave_transaction_id = transfer_resp.get("transfer_id")
            await add_ledger_entry(
                user_fresh.id, -req.montant, user_fresh.solde,
                "Retrait wallet", tx_fresh.id, db
            )
        else:
            user_fresh.solde += req.montant
            user_fresh.version += 1
            tx_fresh.status = "failed"
            tx_fresh.error_message = "Échec transfert Wave"

    if wave_status == "failed":
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Erreur lors du transfert Wave. Solde remboursé.")

    return {"ok": True, "message": "Retrait en cours de traitement"}


@app.post("/users/me/transfer")
async def transfer(
    req: TransferRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if current_user.bloque:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte bloqué")

    await rate_limit_check(f"transfer:{current_user.id}", settings.RATE_LIMIT_TRANSFER, 60, request)
    await check_kyc_limits(current_user, req.montant, "withdraw")

    if not await verify_otp(current_user.id, "transfer", req.otp, db, request):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP invalide")
    if not await verify_pin(current_user, req.pin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "PIN incorrect")

    try:
        phone_e164 = phonenumbers.format_number(
            parse_phone(req.telephone, None),
            phonenumbers.PhoneNumberFormat.E164
        )
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Numéro destinataire invalide")

    result = await db.execute(select(UserDB).where(UserDB.telephone == phone_e164))
    recipient = result.scalar_one_or_none()

    if not recipient:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Destinataire non trouvé")
    if recipient.id == current_user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Transfert à soi-même interdit")
    if recipient.bloque:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Compte destinataire bloqué")

    transfer_ref = f"transfer_{uuid.uuid4().hex}"

    async with db.begin():
        stmt_sender = select(UserDB).where(
            UserDB.id == current_user.id,
            UserDB.version == current_user.version
        ).with_for_update()
        sender = (await db.execute(stmt_sender)).scalar_one_or_none()

        if not sender:
            raise HTTPException(status.HTTP_409_CONFLICT, "Conflit de version, réessayez")
        if sender.solde < req.montant:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Solde insuffisant")

        stmt_recipient = select(UserDB).where(
            UserDB.id == recipient.id
        ).with_for_update()
        locked_recipient = (await db.execute(stmt_recipient)).scalar_one_or_none()

        if not locked_recipient:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Destinataire non trouvé")

        sender.solde -= req.montant
        sender.version += 1
        locked_recipient.solde += req.montant
        locked_recipient.version += 1

        tx_send = TransactionDB(
            user_id=sender.id,
            montant=-req.montant,
            currency=sender.currency,
            type="transfer_sent",
            status="success",
            external_reference=f"send_{transfer_ref}"
        )
        tx_recv = TransactionDB(
            user_id=locked_recipient.id,
            montant=req.montant,
            currency=locked_recipient.currency,
            type="transfer_received",
            status="success",
            external_reference=f"recv_{transfer_ref}"
        )
        db.add_all([tx_send, tx_recv])
        await db.flush()

        await add_ledger_entry(
            sender.id, -req.montant, sender.solde,
            f"Transfert vers {locked_recipient.telephone}", tx_send.id, db
        )
        await add_ledger_entry(
            locked_recipient.id, req.montant, locked_recipient.solde,
            f"Transfert de {sender.telephone}", tx_recv.id, db
        )
        await update_score(sender, "paiement", db)

    return {"ok": True, "message": f"Transfert de {req.montant} FCFA vers {phone_e164} effectué"}


@app.get("/users/me/stats")
async def user_stats(
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    tontines_count_result = await db.execute(
        select(func.count()).select_from(TontineMembreDB)
        .where(TontineMembreDB.user_id == current_user.id)
    )
    total_cotise_result = await db.execute(
        select(func.sum(CotisationDB.montant))
        .where(CotisationDB.user_id == current_user.id, CotisationDB.status == "success")
    )
    total_recu_result = await db.execute(
        select(func.sum(TourDB.montant_percu))
        .where(TourDB.beneficiaire_id == current_user.id)
    )
    return {
        "tontines_count": tontines_count_result.scalar() or 0,
        "total_cotise": str(total_cotise_result.scalar() or Decimal("0")),
        "total_recu": str(total_recu_result.scalar() or Decimal("0")),
        "solde": str(current_user.solde),
        "epargne": str(current_user.epargne),
        "score": current_user.score
    }


@app.post("/users/me/kyc/upload")
async def upload_kyc(
    doc_type: str,
    file: UploadFile = File(...),
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    url = await save_upload_file(file)
    kyc_doc = KycDocumentDB(
        user_id=current_user.id,
        type=doc_type,
        url=url,
        status="pending"
    )
    db.add(kyc_doc)
    current_user.kyc_status = KycStatus.PENDING
    await db.commit()
    return {"ok": True, "message": "Document soumis. En attente d'approbation."}


@app.post("/users/me/device-token")
async def register_device_token(
    req: DeviceTokenRequest,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    existing = await db.execute(select(DeviceTokenDB).where(DeviceTokenDB.token == req.token))
    if existing.scalar_one_or_none():
        return {"ok": True}
    device = DeviceTokenDB(user_id=current_user.id, token=req.token, platform=req.platform)
    db.add(device)
    await db.commit()
    return {"ok": True}


# =====================================================
# MARKETPLACE
# =====================================================
@app.get("/products", response_model=List[ProduitOut])
async def list_products(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 20
):
    limit = min(limit, 100)
    result = await db.execute(
        select(ProduitDB).where(ProduitDB.stock > 0)
        .order_by(ProduitDB.created_at.desc())
        .offset(skip).limit(limit)
    )
    return result.scalars().all()


@app.post("/users/me/products", response_model=ProduitOut, status_code=status.HTTP_201_CREATED)
async def add_product(
    product_data: ProduitCreate,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    produit = ProduitDB(
        vendeur_id=current_user.id,
        nom=product_data.nom,
        description=product_data.description,
        prix=product_data.prix,
        currency=current_user.currency,
        stock=product_data.stock,
        image_url=product_data.image_url
    )
    db.add(produit)
    await db.commit()
    await db.refresh(produit)
    return produit


@app.post("/users/me/products/upload")
async def upload_product_image(
    file: UploadFile = File(...),
    current_user: UserDB = Depends(get_current_user)
):
    """Endpoint pour uploader une image de produit et obtenir son URL"""
    url = await save_upload_file(file, allowed_types=["image/jpeg", "image/png", "image/jpg"])
    return {"image_url": url}


@app.post("/users/me/buy/{produit_id}")
async def buy_product(
    produit_id: str,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"buy:{current_user.id}", settings.RATE_LIMIT_BUY, 60, request)

    async with db.begin():
        produit = await db.get(ProduitDB, produit_id, with_for_update=True)
        if not produit or produit.stock <= 0:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Produit non trouvé ou en rupture de stock")

        user = await db.get(UserDB, current_user.id, with_for_update=True)
        if not user or user.version != current_user.version:
            raise HTTPException(status.HTTP_409_CONFLICT, "Conflit de version, réessayez")
        if user.solde < produit.prix:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Solde insuffisant")

        vendeur = await db.get(UserDB, produit.vendeur_id, with_for_update=True)
        if not vendeur:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Vendeur introuvable")

        user.solde -= produit.prix
        user.version += 1
        vendeur.solde += produit.prix
        vendeur.version += 1
        produit.stock -= 1

        transaction = TransactionDB(
            user_id=user.id,
            montant=-produit.prix,
            currency=user.currency,
            type="achat",
            status="success",
            produit_id=produit.id,
            external_reference=f"achat_{uuid.uuid4().hex}"
        )
        db.add(transaction)
        await db.flush()

        await add_ledger_entry(user.id, -produit.prix, user.solde, f"Achat {produit.nom}", transaction.id, db)
        await add_ledger_entry(vendeur.id, produit.prix, vendeur.solde, f"Vente {produit.nom}", transaction.id, db)
        await update_score(user, "achat", db)
        await update_score(vendeur, "vente", db)

    return {"ok": True, "message": "Achat effectué avec succès"}


@app.get("/products/suggestions")
async def get_suggestions(
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    suggestions = await suggerer_produits(current_user, db)
    return {"suggestions": suggestions}


# =====================================================
# ENDPOINTS TONTINE
# =====================================================
@app.get("/tontines", response_model=List[TontineOut])
async def list_tontines(
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(TontineMembreDB.tontine_id)
        .where(TontineMembreDB.user_id == current_user.id)
    )
    tontine_ids = [row.tontine_id for row in result.all()]
    if not tontine_ids:
        return []
    tontines = await db.execute(
        select(TontineDB).where(TontineDB.id.in_(tontine_ids))
    )
    return tontines.scalars().all()


@app.post("/tontines", response_model=TontineOut, status_code=status.HTTP_201_CREATED)
async def create_tontine(
    data: TontineCreate,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"create_tontine:{current_user.id}", settings.RATE_LIMIT_CREATE_TONTINE, 300, request)

    tontine = TontineDB(
        nom=data.nom,
        description=data.description,
        montant_cotisation=data.montant_cotisation,
        currency=current_user.currency,
        frequence=data.frequence,
        mode_tirage=data.mode_tirage,
        admin_id=current_user.id,
        quorum=data.quorum,
    )
    db.add(tontine)
    await db.flush()

    membre_admin = TontineMembreDB(
        tontine_id=tontine.id,
        user_id=current_user.id,
        role="admin",
        statut="actif",
        ordre=1 if data.mode_tirage == "ordre_fixe" else None,
    )
    db.add(membre_admin)

    ordre = 2 if data.mode_tirage == "ordre_fixe" else None
    for tel in data.participants_telephones:
        try:
            user = await get_or_create_user_by_telephone(tel, db)
        except ValueError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

        existant = await db.execute(
            select(TontineMembreDB).where(
                TontineMembreDB.tontine_id == tontine.id,
                TontineMembreDB.user_id == user.id
            )
        )
        if not existant.scalar_one_or_none():
            membre = TontineMembreDB(
                tontine_id=tontine.id,
                user_id=user.id,
                role="membre",
                statut="invite",
                ordre=ordre,
            )
            db.add(membre)
            if ordre is not None:
                ordre += 1

    await initialiser_tour(tontine, db)
    await db.commit()
    await db.refresh(tontine)
    return tontine


@app.patch("/tontines/{tontine_id}")
async def update_tontine(
    tontine_id: str,
    update_data: TontineUpdate,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    tontine = await db.get(TontineDB, tontine_id, with_for_update=True)
    if not tontine:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tontine non trouvée")
    if tontine.admin_id != current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Seul l'administrateur peut modifier")

    for key, value in update_data.model_dump(exclude_unset=True).items():
        setattr(tontine, key, value)
    tontine.version += 1
    await db.commit()
    return {"ok": True}


@app.post("/tontines/{tontine_id}/invite")
async def invite_member(
    tontine_id: str,
    invite_data: InviteRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"invite:{current_user.id}", settings.RATE_LIMIT_INVITE, 300, request)

    tontine = await db.get(TontineDB, tontine_id, with_for_update=True)
    if not tontine:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tontine non trouvée")
    if tontine.admin_id != current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Seul l'administrateur peut inviter")

    try:
        user = await get_or_create_user_by_telephone(invite_data.telephone, db)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    existant = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine_id,
            TontineMembreDB.user_id == user.id
        )
    )
    if existant.scalar_one_or_none():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Utilisateur déjà membre")

    ordre = None
    if tontine.mode_tirage == "ordre_fixe":
        max_ordre_result = await db.execute(
            select(func.max(TontineMembreDB.ordre))
            .where(TontineMembreDB.tontine_id == tontine_id)
        )
        max_ordre = max_ordre_result.scalar() or 0
        ordre = max_ordre + 1

    membre = TontineMembreDB(
        tontine_id=tontine_id,
        user_id=user.id,
        role="membre",
        statut="invite",
        ordre=ordre,
    )
    db.add(membre)
    await db.commit()

    await create_notification(
        user.id, "sms",
        "Invitation tontine",
        f"Vous avez été invité à rejoindre la tontine '{tontine.nom}'. Connectez-vous pour accepter.",
        db
    )
    await db.commit()
    return {"ok": True, "message": f"Invitation envoyée à {invite_data.telephone}"}


@app.post("/tontines/{tontine_id}/join")
async def join_tontine(
    tontine_id: str,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    tontine = await db.get(TontineDB, tontine_id)
    if not tontine:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tontine non trouvée")
    if tontine.statut != "active":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Tontine inactive")

    membre_result = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine_id,
            TontineMembreDB.user_id == current_user.id
        ).with_for_update()
    )
    membre = membre_result.scalar_one_or_none()

    if not membre:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vous n'avez pas été invité dans cette tontine")
    if membre.statut != "invite":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Statut actuel: {membre.statut}")

    membre.statut = "actif"
    membre.version += 1
    await db.commit()
    return {"ok": True, "message": "Vous avez rejoint la tontine"}


@app.post("/tontines/{tontine_id}/leave")
async def leave_tontine(
    tontine_id: str,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    tontine = await db.get(TontineDB, tontine_id, with_for_update=True)
    if not tontine:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tontine non trouvée")
    if not tontine.autoriser_sortie_anticipee:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cette tontine n'autorise pas les sorties anticipées")

    membre_result = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine_id,
            TontineMembreDB.user_id == current_user.id,
            TontineMembreDB.statut == "actif"
        ).with_for_update()
    )
    membre = membre_result.scalar_one_or_none()

    if not membre:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vous n'êtes pas membre actif de cette tontine")

    montant_a_rembourser = membre.montant_cotise_total or Decimal("0.00")

    if montant_a_rembourser > 0:
        user = await db.get(UserDB, current_user.id, with_for_update=True)
        user.solde += montant_a_rembourser
        user.version += 1

        tx = TransactionDB(
            user_id=user.id,
            montant=montant_a_rembourser,
            currency=user.currency,
            type="remboursement_sortie",
            status="success",
            tontine_id=tontine_id,
            external_reference=f"sortie_{uuid.uuid4().hex}"
        )
        db.add(tx)
        await db.flush()
        await add_ledger_entry(
            user.id, montant_a_rembourser, user.solde,
            "Remboursement sortie tontine", tx.id, db
        )

    membre.statut = "sorti"
    membre.version += 1
    await db.commit()
    return {
        "ok": True,
        "message": f"Vous avez quitté la tontine.",
        "montant_rembourse": str(montant_a_rembourser)
    }


@app.post("/tontines/{tontine_id}/cotiser")
async def cotiser(
    tontine_id: str,
    cotisation_data: CotisationRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"cotiser:{current_user.id}", settings.RATE_LIMIT_COTISER, 60, request)

    tontine = await db.get(TontineDB, tontine_id)
    if not tontine:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tontine non trouvée")
    if tontine.statut != "active":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Tontine inactive")

    membre_result = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine_id,
            TontineMembreDB.user_id == current_user.id
        ).with_for_update()
    )
    membre = membre_result.scalar_one_or_none()

    if not membre or membre.statut not in ["actif"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Vous n'êtes pas membre actif de cette tontine")

    cotisation_existante_result = await db.execute(
        select(CotisationDB).where(
            CotisationDB.tontine_id == tontine_id,
            CotisationDB.user_id == current_user.id,
            CotisationDB.cycle_id == tontine.cycle_actuel,
            CotisationDB.status.in_(["success", "pending"])
        )
    )
    if cotisation_existante_result.scalar_one_or_none():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Vous avez déjà cotisé (ou une cotisation est en attente) pour ce cycle")

    penalite = Decimal("0.00")
    if tontine.autoriser_penalites:
        tour_result = await db.execute(
            select(TourDB).where(
                TourDB.tontine_id == tontine_id,
                TourDB.numero_cycle == tontine.cycle_actuel
            )
        )
        tour = tour_result.scalar_one_or_none()
        if tour and tour.date_debut:
            date_limite = tour.date_debut + timedelta(days=3)
            if datetime.now(timezone.utc) > date_limite:
                penalite = (tontine.montant_cotisation * Decimal("0.02")).quantize(
                    Decimal("0.01"), rounding=ROUND_DOWN
                )

    montant_total = tontine.montant_cotisation + penalite
    external_ref = f"cotisation_{uuid.uuid4().hex}"
    gateway = PaymentGatewayFactory.get_gateway("wave")

    try:
        wave_resp = await gateway.create_payment_request(
            amount=montant_total,
            phone=current_user.telephone,
            reference=external_ref,
            description=cotisation_data.description or f"Cotisation {tontine.nom} cycle {tontine.cycle_actuel}"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur Wave cotisation: {e}")
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Erreur lors de l'initiation du paiement")

    cotisation = CotisationDB(
        tontine_id=tontine_id,
        user_id=current_user.id,
        montant=tontine.montant_cotisation,
        penalite=penalite,
        cycle_id=tontine.cycle_actuel,
        status="pending",
        external_reference=external_ref,
        wave_transaction_id=wave_resp.get("request_id")
    )
    db.add(cotisation)
    await db.commit()

    return {
        "checkout_url": wave_resp.get("checkout_url"),
        "cotisation_id": cotisation.id,
        "penalite": str(penalite),
        "message": "Veuillez valider le paiement Wave"
    }


@app.post("/tontines/{tontine_id}/retrait")
async def retrait_beneficiaire(
    tontine_id: str,
    retrait_data: RetraitRequest,
    request: Request,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    await rate_limit_check(f"retrait_tontine:{current_user.id}", settings.RATE_LIMIT_WITHDRAW, 60, request)

    tontine = await db.get(TontineDB, tontine_id, with_for_update=True)
    if not tontine:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tontine non trouvée")
    if tontine.statut != "active":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Tontine inactive")
    if tontine.beneficiaire_actuel_id != current_user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Seul le bénéficiaire actuel peut retirer")

    if not await verify_otp(current_user.id, "withdraw", retrait_data.otp, db, request):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Code OTP invalide ou expiré")
    if not await verify_pin(current_user, retrait_data.pin):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "PIN incorrect")

    tour_result = await db.execute(
        select(TourDB).where(
            TourDB.tontine_id == tontine_id,
            TourDB.numero_cycle == tontine.cycle_actuel
        ).with_for_update()
    )
    tour = tour_result.scalar_one_or_none()
    if not tour or tour.status != "en_cours":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Aucun tour en cours ou déjà clôturé")

    cotisations_result = await db.execute(
        select(func.sum(CotisationDB.montant + CotisationDB.penalite)).where(
            CotisationDB.tontine_id == tontine_id,
            CotisationDB.cycle_id == tontine.cycle_actuel,
            CotisationDB.status == "success"
        )
    )
    disponible = cotisations_result.scalar() or Decimal("0.00")

    if disponible <= 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Aucun fonds disponible pour le retrait")

    montant_retrait = retrait_data.montant
    if montant_retrait > disponible:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Montant demandé ({montant_retrait}) supérieur au disponible ({disponible})"
        )

    reference = f"payout_{tour.id}"
    existing_tx_result = await db.execute(
        select(TransactionDB).where(TransactionDB.external_reference == reference)
    )
    if existing_tx_result.scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Transfert déjà en cours ou effectué")

    tour.status = "processing"
    await db.commit()

    gateway = PaymentGatewayFactory.get_gateway("wave")
    try:
        wave_resp = await gateway.transfer(
            amount=montant_retrait,
            recipient_phone=current_user.telephone,
            reference=reference,
            description=f"Paiement tontine {tontine.nom} cycle {tontine.cycle_actuel}"
        )
    except HTTPException:
        tour.status = "en_cours"
        await db.commit()
        raise
    except Exception as e:
        logger.error(f"Erreur transfert tontine: {e}")
        tour.status = "en_cours"
        await db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Erreur lors du paiement")

    commission = (montant_retrait * tontine.commission_plateforme).quantize(
        Decimal("0.01"), rounding=ROUND_DOWN
    )

    tour.montant_percu = montant_retrait
    tour.payout_wave_transaction_id = wave_resp.get("transfer_id")
    tour.status = "paye"
    tour.date_fin = datetime.now(timezone.utc)
    tour.commission_plateforme = commission

    tx_commission = TransactionDB(
        user_id=settings.PLATFORM_ACCOUNT_ID,
        montant=commission,
        currency=tontine.currency,
        type="commission",
        status="success",
        tontine_id=tontine_id,
        cycle_id=tontine.cycle_actuel,
        external_reference=f"commission_{reference}"
    )
    db.add(tx_commission)

    tontine.cycle_actuel += 1
    tontine.montant_collecte_cycle = Decimal("0.00")
    await initialiser_tour(tontine, db)
    await db.commit()

    await create_notification(
        current_user.id, "sms",
        "Paiement reçu",
        f"Vous avez reçu {montant_retrait} FCFA de la tontine {tontine.nom}.",
        db
    )
    await db.commit()
    return {"ok": True, "message": f"Retrait de {montant_retrait} FCFA effectué"}


@app.get("/tontines/{tontine_id}/members", response_model=List[TontineMembreOut])
async def get_tontine_members(
    tontine_id: str,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    membre_check = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine_id,
            TontineMembreDB.user_id == current_user.id
        )
    )
    if not membre_check.scalar_one_or_none():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès non autorisé")

    result = await db.execute(
        select(TontineMembreDB).where(TontineMembreDB.tontine_id == tontine_id)
        .order_by(TontineMembreDB.ordre)
    )
    return result.scalars().all()


@app.get("/tontines/{tontine_id}/cotisations", response_model=List[CotisationOut])
async def get_cotisations(
    tontine_id: str,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    cycle_id: Optional[int] = None
):
    membre_check = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine_id,
            TontineMembreDB.user_id == current_user.id
        )
    )
    if not membre_check.scalar_one_or_none():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Accès non autorisé")

    query = select(CotisationDB).where(CotisationDB.tontine_id == tontine_id)
    if cycle_id:
        query = query.where(CotisationDB.cycle_id == cycle_id)
    result = await db.execute(query.order_by(CotisationDB.date.desc()))
    return result.scalars().all()


@app.get("/tontines/{tontine_id}/messages", response_model=List[MessageOut])
async def get_messages(
    tontine_id: str,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 50
):
    membre_check = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine_id,
            TontineMembreDB.user_id == current_user.id
        )
    )
    if not membre_check.scalar_one_or_none():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Vous n'êtes pas membre de cette tontine")

    result = await db.execute(
        select(MessageDB).where(MessageDB.tontine_id == tontine_id)
        .order_by(MessageDB.created_at.desc())
        .offset(skip).limit(min(limit, 100))
    )
    return result.scalars().all()


@app.post("/tontines/{tontine_id}/messages", status_code=status.HTTP_201_CREATED)
async def post_message(
    tontine_id: str,
    msg: MessageCreate,
    current_user: UserDB = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    membre_check = await db.execute(
        select(TontineMembreDB).where(
            TontineMembreDB.tontine_id == tontine_id,
            TontineMembreDB.user_id == current_user.id,
            TontineMembreDB.statut == "actif"
        )
    )
    if not membre_check.scalar_one_or_none():
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Vous n'êtes pas membre actif de cette tontine")

    message = MessageDB(
        tontine_id=tontine_id,
        user_id=current_user.id,
        content=msg.content
    )
    db.add(message)
    await db.commit()
    return {"ok": True}


@app.get("/help", response_model=List[HelpArticleOut])
async def get_help_articles(lang: str = "fr", category: Optional[str] = None):
    async with AsyncSessionLocal() as db:
        query = select(HelpArticle).where(HelpArticle.lang == lang)
        if category:
            query = query.where(HelpArticle.category == category)
        result = await db.execute(query.order_by(HelpArticle.order))
        return result.scalars().all()


# =====================================================
# WEBHOOK WAVE
# =====================================================
@app.post("/webhook/wave")
async def wave_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    payload = await request.body()
    headers = dict(request.headers)

    gateway = PaymentGatewayFactory.get_gateway("wave")
    if not gateway.verify_webhook(payload, headers):
        logger.warning("Webhook Wave avec signature invalide")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Signature invalide")

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Payload invalide")

    event_type = data.get("event")
    if event_type not in ("transaction.updated", "transfer.updated"):
        return {"ok": True, "skipped": True}

    tx_data = data.get("data", {})
    wave_tx_id = tx_data.get("id")
    wave_status = tx_data.get("status")
    external_ref = tx_data.get("reference")

    if not external_ref:
        logger.warning(f"Webhook Wave sans reference: {data}")
        return {"ok": True}

    processed_result = await db.execute(
        select(ProcessedWebhook).where(ProcessedWebhook.external_reference == external_ref)
    )
    if processed_result.scalar_one_or_none():
        return {"ok": True, "already_processed": True}

    tx_result = await db.execute(
        select(TransactionDB).where(
            (TransactionDB.wave_transaction_id == wave_tx_id) |
            (TransactionDB.external_reference == external_ref)
        ).with_for_update()
    )
    tx = tx_result.scalar_one_or_none()

    if tx and tx.status in ("pending", "pending_wave"):
        if wave_status == "completed":
            tx.status = "success"
            tx.wave_transaction_id = wave_tx_id

            if tx.type == "deposit":
                user = await db.get(UserDB, tx.user_id, with_for_update=True)
                if user:
                    user.solde += tx.montant
                    user.version += 1
                    await add_ledger_entry(
                        user.id, tx.montant, user.solde,
                        "Dépôt Wave confirmé", tx.id, db
                    )
                    await update_score(user, "paiement", db)
        elif wave_status in ("failed", "cancelled"):
            if tx.type == "deposit":
                tx.status = "failed"
            elif tx.type == "withdraw":
                user = await db.get(UserDB, tx.user_id, with_for_update=True)
                if user and tx.status == "pending_wave":
                    user.solde += abs(tx.montant)
                    user.version += 1
                    await add_ledger_entry(
                        user.id, abs(tx.montant), user.solde,
                        "Remboursement retrait échoué", tx.id, db
                    )
                tx.status = "failed"
            tx.error_message = f"Wave status: {wave_status}"

        db.add(tx)

    cotisation_result = await db.execute(
        select(CotisationDB).where(
            CotisationDB.external_reference == external_ref
        ).with_for_update()
    )
    cotisation = cotisation_result.scalar_one_or_none()

    if cotisation and cotisation.status == "pending":
        if wave_status == "completed":
            cotisation.status = "success"
            cotisation.wave_transaction_id = wave_tx_id

            tontine = await db.get(TontineDB, cotisation.tontine_id, with_for_update=True)
            if tontine:
                tontine.montant_collecte_cycle += cotisation.montant + cotisation.penalite

            membre_result = await db.execute(
                select(TontineMembreDB).where(
                    TontineMembreDB.tontine_id == cotisation.tontine_id,
                    TontineMembreDB.user_id == cotisation.user_id
                ).with_for_update()
            )
            membre = membre_result.scalar_one_or_none()
            if membre:
                membre.montant_cotise_total += cotisation.montant + cotisation.penalite
                membre.derniere_cotisation = datetime.now(timezone.utc)

            if tontine:
                await verifier_et_cloturer_cycle(tontine, db)

        elif wave_status in ("failed", "cancelled"):
            cotisation.status = "failed"

        db.add(cotisation)

    processed_entry = ProcessedWebhook(external_reference=external_ref)
    db.add(processed_entry)
    await db.commit()

    return {"ok": True}


# =====================================================
# ENDPOINTS ADMIN
# =====================================================
@app.get("/admin/users")
async def admin_list_users(
    admin: UserDB = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 50,
    cursor_id: Optional[str] = None,
    blocked: Optional[bool] = None,
    kyc_level: Optional[KycLevel] = None,
    kyc_status: Optional[KycStatus] = None
):
    limit = min(limit, 200)
    query = select(UserDB)

    if blocked is not None:
        query = query.where(UserDB.bloque == blocked)
    if kyc_level:
        query = query.where(UserDB.kyc_level == kyc_level)
    if kyc_status:
        query = query.where(UserDB.kyc_status == kyc_status)

    if cursor_id:
        query = query.where(UserDB.id > cursor_id)

    query = query.order_by(UserDB.id).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()
    return {
        "users": [user_to_out(u) for u in users],
        "next_cursor": users[-1].id if len(users) == limit else None
    }


@app.patch("/admin/users/{user_id}")
async def admin_update_user(
    user_id: str,
    update_data: AdminUserUpdate,
    admin: UserDB = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    user = await db.get(UserDB, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur non trouvé")
    for key, value in update_data.model_dump(exclude_unset=True).items():
        setattr(user, key, value)
    await db.commit()
    return {"ok": True}


@app.post("/admin/kyc/approve")
async def admin_approve_kyc(
    req: KycApproveRequest,
    admin: UserDB = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    user = await db.get(UserDB, req.user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Utilisateur non trouvé")

    if req.status == KycStatus.VERIFIED:
        user.kyc_status = KycStatus.VERIFIED
        user.kyc_level = req.level
        user.kyc_verified_at = datetime.now(timezone.utc)
        user.kyc_verified_by = admin.id
        msg = f"KYC approuvé. Niveau: {req.level.value}"
    elif req.status == KycStatus.REJECTED:
        user.kyc_status = KycStatus.REJECTED
        msg = "KYC rejeté. Veuillez soumettre de nouveaux documents."
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Statut invalide")

    await db.commit()
    await create_notification(user.id, "email", "KYC mis à jour", msg, db)
    await db.commit()
    return {"ok": True}


@app.post("/admin/tasks/send_reminders")
async def admin_send_reminders(
    admin: UserDB = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    tontines_result = await db.execute(
        select(TontineDB).where(TontineDB.statut == "active")
    )
    for tontine in tontines_result.scalars().all():
        await envoyer_rappel_cotisation(tontine, db)
    await db.commit()
    return {"ok": True, "message": "Rappels envoyés"}


@app.get("/admin/stats")
async def admin_stats(
    admin: UserDB = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    total_users = await db.execute(select(func.count()).select_from(UserDB))
    total_tontines = await db.execute(select(func.count()).select_from(TontineDB))
    total_transactions = await db.execute(select(func.count()).select_from(TransactionDB))
    total_volume = await db.execute(
        select(func.sum(TransactionDB.montant))
        .where(TransactionDB.status == "success", TransactionDB.montant > 0)
    )
    total_commission = await db.execute(
        select(func.sum(TransactionDB.montant))
        .where(TransactionDB.type == "commission", TransactionDB.status == "success")
    )
    return {
        "total_users": total_users.scalar() or 0,
        "total_tontines": total_tontines.scalar() or 0,
        "total_transactions": total_transactions.scalar() or 0,
        "total_volume_fcfa": str(total_volume.scalar() or 0),
        "total_commission_fcfa": str(total_commission.scalar() or 0),
    }


@app.get("/admin/kyc/pending")
async def admin_kyc_pending(
    admin: UserDB = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    docs_result = await db.execute(
        select(KycDocumentDB).where(KycDocumentDB.status == "pending")
        .order_by(KycDocumentDB.created_at)
    )
    docs = docs_result.scalars().all()
    return [{"id": d.id, "user_id": d.user_id, "type": d.type, "url": d.url, "created_at": d.created_at} for d in docs]


# =====================================================
# ROUTES UTILITAIRES
# =====================================================
@app.get("/")
async def root():
    return {
        "message": "Bienvenue sur l'API Tamba",
        "version": "14.0",
        "docs": "/docs" if settings.ENVIRONMENT != "production" else "disabled"
    }


@app.get("/health")
async def health():
    redis_status = "ok"
    try:
        r = await get_redis()
        if r is None:
            redis_status = "unavailable"
        else:
            await r.ping()
    except Exception:
        redis_status = "error"

    db_status = "ok"
    try:
        async with engine.connect() as conn:
            await conn.execute(select(func.now()))
    except Exception:
        db_status = "error"

    overall = "ok" if db_status == "ok" and redis_status in ("ok", "unavailable") else "degraded"
    return {
        "status": overall,
        "version": "14.0",
        "environment": settings.ENVIRONMENT,
        "redis": redis_status,
        "db": db_status
    }


# =====================================================
# LANCEMENT
# =====================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.ENVIRONMENT == "development",
        log_level="debug" if settings.DEBUG else "info",
    )
    
