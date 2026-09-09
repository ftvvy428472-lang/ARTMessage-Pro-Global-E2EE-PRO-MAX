# -*- coding: utf-8 -*-
"""
ARTMessage Backend
===================
Полноценный бэкенд для мессенджера "ARTMessage".

Технологии: FastAPI + SQLAlchemy (SQLite) + WebSocket + JWT + bcrypt.

Запуск (локально):
    uvicorn server:app --reload

Запуск (продакшн, например Render):
    uvicorn server:app --host 0.0.0.0 --port $PORT
"""

import os
import uuid
import shutil
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict

import jwt  # PyJWT
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    UploadFile,
    File,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel, Field, ConfigDict

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    or_,
    and_,
    func,
)
from sqlalchemy.orm import sessionmaker, relationship, declarative_base, Session

from passlib.context import CryptContext

from apscheduler.schedulers.background import BackgroundScheduler


# =========================================================================
# ЛОГИРОВАНИЕ
# =========================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("artmessage")


# =========================================================================
# КОНФИГУРАЦИЯ
# =========================================================================
# В продакшне обязательно задайте переменную окружения JWT_SECRET_KEY!
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "artmessage-dev-secret-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_TEMP_DIR = os.path.join(BASE_DIR, "uploads", "temp")
UPLOAD_AVATAR_DIR = os.path.join(BASE_DIR, "uploads", "avatars")
MAX_FILE_SIZE_BYTES = 500 * 1024  # 500 КБ
TEMP_FILE_TTL_MINUTES = 15
CLEANUP_INTERVAL_MINUTES = 5
MESSAGES_PAGE_SIZE = 20

DATABASE_URL = "sqlite:///./database.db"


# =========================================================================
# БАЗА ДАННЫХ
# =========================================================================
# check_same_thread=False нужен, т.к. SQLite + FastAPI работают в разных потоках
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def utcnow() -> datetime:
    """Текущее время в UTC (без tzinfo, для совместимости со SQLite)."""
    return datetime.utcnow()


# =========================================================================
# МОДЕЛИ SQLAlchemy
# =========================================================================
class User(Base):
    """Пользователь мессенджера."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=True)
    bio = Column(String, nullable=True)
    password_hash = Column(String, nullable=False)
    avatar_url = Column(String, nullable=True)
    public_key = Column(String, nullable=False)  # RSA публичный ключ клиента (для E2EE)
    hardware_id = Column(String, unique=True, nullable=False)  # fingerprint устройства
    is_online = Column(Boolean, default=False, nullable=False)
    last_seen = Column(DateTime, default=utcnow, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class Chat(Base):
    """Чат: приватный диалог, группа или канал."""
    __tablename__ = "chats"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String, nullable=False)  # 'private' | 'group' | 'channel'
    name = Column(String, nullable=True)
    description = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    members = relationship("ChatMember", back_populates="chat", cascade="all, delete-orphan")
    messages = relationship("Message", back_populates="chat", cascade="all, delete-orphan")


class ChatMember(Base):
    """Связь пользователь <-> чат (участие в чате)."""
    __tablename__ = "chat_members"

    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role = Column(String, default="member", nullable=False)  # 'admin' | 'member' | 'creator'
    is_pinned = Column(Boolean, default=False, nullable=False)
    folder = Column(String, nullable=True)
    joined_at = Column(DateTime, default=utcnow, nullable=False)

    chat = relationship("Chat", back_populates="members")

    __table_args__ = (UniqueConstraint("chat_id", "user_id", name="uq_chat_member"),)


class Message(Base):
    """Сообщение в чате. Содержимое хранится в зашифрованном виде (E2EE) — сервер его не читает."""
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String, unique=True, index=True, nullable=False)  # UUID сообщения
    send_id = Column(String, index=True, nullable=False)  # UUID пары отправитель-получатель
    chat_id = Column(Integer, ForeignKey("chats.id"), nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content = Column(String, nullable=False)  # зашифрованный текст
    file_url = Column(String, nullable=True)
    file_type = Column(String, nullable=True)  # 'image' | 'document'
    file_name = Column(String, nullable=True)
    is_read = Column(Boolean, default=False, nullable=False)
    read_at = Column(DateTime, nullable=True)
    delivered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    chat = relationship("Chat", back_populates="messages")


class UserBlock(Base):
    """Блокировка одного пользователя другим."""
    __tablename__ = "user_blocks"

    id = Column(Integer, primary_key=True, index=True)
    blocker_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    blocked_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("blocker_id", "blocked_id", name="uq_user_block"),)


# =========================================================================
# PYDANTIC СХЕМЫ
# =========================================================================
class RegisterIn(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    first_name: str = Field(..., min_length=1, max_length=64)
    last_name: Optional[str] = None
    bio: Optional[str] = None
    password: str = Field(..., min_length=6)
    public_key: str
    hardware_id: str
    avatar_url: Optional[str] = None


class LoginIn(BaseModel):
    username: str
    password: str
    hardware_id: str


class RefreshIn(BaseModel):
    refresh_token: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    username: str
    first_name: str
    last_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    public_key: str
    is_online: bool
    last_seen: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserUpdateIn(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=32)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = None


class PasswordUpdateIn(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)


class ChatCreateIn(BaseModel):
    type: str = Field(..., pattern="^(private|group|channel)$")
    name: Optional[str] = None
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    member_ids: List[int] = Field(default_factory=list)


class ChatOut(BaseModel):
    id: int
    type: str
    name: Optional[str] = None
    description: Optional[str] = None
    avatar_url: Optional[str] = None
    created_by: int
    created_at: datetime
    is_pinned: Optional[bool] = None
    folder: Optional[str] = None
    role: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class FolderUpdateIn(BaseModel):
    folder: Optional[str] = None


class RoleUpdateIn(BaseModel):
    role: str = Field(..., pattern="^(admin|member|creator)$")


class AddMemberIn(BaseModel):
    user_id: int


class MessageCreateIn(BaseModel):
    message_id: str
    send_id: str
    content: str
    file_url: Optional[str] = None
    file_type: Optional[str] = None
    file_name: Optional[str] = None


class MessageOut(BaseModel):
    id: int
    message_id: str
    send_id: str
    chat_id: int
    sender_id: int
    content: str
    file_url: Optional[str] = None
    file_type: Optional[str] = None
    file_name: Optional[str] = None
    is_read: bool
    read_at: Optional[datetime] = None
    delivered_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================================================================
# УТИЛИТЫ: ПАРОЛИ И JWT
# =========================================================================
# bcrypt с 12 раундами, как требуется в ТЗ
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# Список отозванных токенов (jti). В продакшне лучше вынести в Redis,
# но для простоты храним в памяти процесса.
revoked_jti: set = set()


def create_token(data: dict, expires_delta: timedelta, token_type: str) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    to_encode.update(
        {
            "exp": now + expires_delta,
            "iat": now,
            "type": token_type,
            "jti": str(uuid.uuid4()),
        }
    )
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_access_token(user_id: int) -> str:
    return create_token({"sub": str(user_id)}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES), "access")


def create_refresh_token(user_id: int) -> str:
    return create_token({"sub": str(user_id)}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), "refresh")


def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Токен истёк")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Невалидный токен")
    if payload.get("jti") in revoked_jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Токен отозван")
    return payload


# =========================================================================
# ЗАВИСИМОСТИ (Depends)
# =========================================================================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется access-токен")
    user_id = payload.get("sub")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Пользователь не найден")
    return user


def get_chat_member_or_404(db: Session, chat_id: int, user_id: int) -> ChatMember:
    member = (
        db.query(ChatMember)
        .filter(ChatMember.chat_id == chat_id, ChatMember.user_id == user_id)
        .first()
    )
    if member is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Вы не участник этого чата")
    return member


def is_blocked(db: Session, blocker_id: int, blocked_id: int) -> bool:
    return (
        db.query(UserBlock)
        .filter(UserBlock.blocker_id == blocker_id, UserBlock.blocked_id == blocked_id)
        .first()
        is not None
    )


# =========================================================================
# WEBSOCKET CONNECTION MANAGER
# =========================================================================
class ConnectionManager:
    """Хранит активные WebSocket-соединения пользователей (один пользователь может иметь
    несколько соединений — например, с разных устройств)."""

    def __init__(self):
        self.active: Dict[int, List[WebSocket]] = {}

    async def connect(self, user_id: int, ws: WebSocket):
        await ws.accept()
        self.active.setdefault(user_id, []).append(ws)

    def disconnect(self, user_id: int, ws: WebSocket):
        if user_id in self.active:
            if ws in self.active[user_id]:
                self.active[user_id].remove(ws)
            if not self.active[user_id]:
                del self.active[user_id]

    async def send_to_user(self, user_id: int, payload: dict):
        for ws in list(self.active.get(user_id, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                logger.warning("Не удалось отправить сообщение пользователю %s", user_id)

    async def broadcast_to_chat(self, db: Session, chat_id: int, payload: dict, exclude_user_id: Optional[int] = None):
        member_ids = [
            m.user_id
            for m in db.query(ChatMember).filter(ChatMember.chat_id == chat_id).all()
            if m.user_id != exclude_user_id
        ]
        for uid in member_ids:
            await self.send_to_user(uid, payload)

    def is_online(self, user_id: int) -> bool:
        return user_id in self.active and len(self.active[user_id]) > 0


manager = ConnectionManager()


# =========================================================================
# ФОНОВЫЕ ЗАДАЧИ
# =========================================================================
def cleanup_temp_files():
    """Удаляет временные файлы старше TEMP_FILE_TTL_MINUTES минут. Запускается по расписанию."""
    try:
        now_ts = datetime.utcnow().timestamp()
        threshold = TEMP_FILE_TTL_MINUTES * 60
        if not os.path.isdir(UPLOAD_TEMP_DIR):
            return
        removed = 0
        for filename in os.listdir(UPLOAD_TEMP_DIR):
            file_path = os.path.join(UPLOAD_TEMP_DIR, filename)
            if os.path.isfile(file_path):
                file_age = now_ts - os.path.getmtime(file_path)
                if file_age > threshold:
                    os.remove(file_path)
                    removed += 1
        if removed:
            logger.info("Автоочистка: удалено временных файлов — %s", removed)
    except Exception as exc:
        logger.error("Ошибка автоочистки временных файлов: %s", exc)


scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_temp_files, "interval", minutes=CLEANUP_INTERVAL_MINUTES, id="cleanup_temp_files")


# =========================================================================
# ИНИЦИАЛИЗАЦИЯ ПРИЛОЖЕНИЯ
# =========================================================================
app = FastAPI(title="ARTMessage API", version="1.0.0")

# CORS открыт для разработки — разрешён любой фронтенд
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    os.makedirs(UPLOAD_TEMP_DIR, exist_ok=True)
    os.makedirs(UPLOAD_AVATAR_DIR, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    scheduler.start()
    logger.info("ARTMessage backend запущен. Таблицы БД созданы, шедулер запущен.")


@app.on_event("shutdown")
def on_shutdown():
    scheduler.shutdown(wait=False)
    logger.info("ARTMessage backend остановлен.")


# Статическая раздача загруженных файлов (аватарки и временные файлы)
app.mount("/static/avatars", StaticFiles(directory=UPLOAD_AVATAR_DIR), name="avatars")


# =========================================================================
# АУТЕНТИФИКАЦИЯ
# =========================================================================
@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED, tags=["auth"])
def register(data: RegisterIn, db: Session = Depends(get_db)):
    """Регистрация нового пользователя."""
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Пользователь с таким username уже существует")
    if db.query(User).filter(User.hardware_id == data.hardware_id).first():
        raise HTTPException(status_code=400, detail="Устройство уже зарегистрировано на другой аккаунт")

    user = User(
        username=data.username,
        first_name=data.first_name,
        last_name=data.last_name,
        bio=data.bio,
        password_hash=hash_password(data.password),
        avatar_url=data.avatar_url,
        public_key=data.public_key,
        hardware_id=data.hardware_id,
    )
    db.add(user)
    try:
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.error("Ошибка регистрации: %s", exc)
        raise HTTPException(status_code=400, detail="Не удалось создать пользователя")
    db.refresh(user)
    logger.info("Зарегистрирован новый пользователь: %s (id=%s)", user.username, user.id)
    return user


@app.post("/auth/login", response_model=TokenOut, tags=["auth"])
def login(data: LoginIn, db: Session = Depends(get_db)):
    """Вход пользователя. Возвращает пару access/refresh токенов."""
    user = db.query(User).filter(User.username == data.username).first()
    if user is None or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")

    # Проверка hardware_id — простая привязка к устройству
    if user.hardware_id != data.hardware_id:
        logger.warning("Вход с нового устройства для пользователя %s", user.username)

    user.is_online = True
    user.last_seen = utcnow()
    db.commit()

    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)
    logger.info("Пользователь %s вошёл в систему", user.username)
    return TokenOut(access_token=access, refresh_token=refresh)


@app.post("/auth/refresh", response_model=TokenOut, tags=["auth"])
def refresh_token_endpoint(data: RefreshIn, db: Session = Depends(get_db)):
    """Обновление access-токена по refresh-токену."""
    payload = decode_token(data.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Требуется refresh-токен")
    user_id = int(payload.get("sub"))
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Пользователь не найден")

    # Старый refresh-токен отзываем, выдаём новую пару (ротация токенов)
    revoked_jti.add(payload.get("jti"))
    new_access = create_access_token(user.id)
    new_refresh = create_refresh_token(user.id)
    return TokenOut(access_token=new_access, refresh_token=new_refresh)


@app.post("/auth/logout", tags=["auth"])
def logout(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Выход из системы: отзывает текущий access-токен и помечает пользователя офлайн."""
    payload = decode_token(token)
    revoked_jti.add(payload.get("jti"))
    user_id = int(payload.get("sub"))
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_online = False
        user.last_seen = utcnow()
        db.commit()
    return {"detail": "Вы успешно вышли из системы"}


# =========================================================================
# ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ
# =========================================================================
@app.get("/user/me", response_model=UserOut, tags=["user"])
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.put("/user/me", response_model=UserOut, tags=["user"])
def update_me(data: UserUpdateIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.username and data.username != current_user.username:
        if db.query(User).filter(User.username == data.username).first():
            raise HTTPException(status_code=400, detail="Username уже занят")
        current_user.username = data.username
    if data.first_name is not None:
        current_user.first_name = data.first_name
    if data.last_name is not None:
        current_user.last_name = data.last_name
    if data.bio is not None:
        current_user.bio = data.bio
    current_user.updated_at = utcnow()
    db.commit()
    db.refresh(current_user)
    return current_user


@app.put("/user/me/password", tags=["user"])
def update_password(data: PasswordUpdateIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(data.old_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Старый пароль неверен")
    current_user.password_hash = hash_password(data.new_password)
    current_user.updated_at = utcnow()
    db.commit()
    return {"detail": "Пароль успешно изменён"}


@app.post("/user/me/avatar", response_model=UserOut, tags=["user"])
def upload_avatar(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ext = os.path.splitext(file.filename or "")[1] or ".jpg"
    filename = f"{current_user.id}_{uuid.uuid4().hex}{ext}"
    dest_path = os.path.join(UPLOAD_AVATAR_DIR, filename)
    try:
        with open(dest_path, "wb") as out_file:
            shutil.copyfileobj(file.file, out_file)
    except Exception as exc:
        logger.error("Ошибка загрузки аватара: %s", exc)
        raise HTTPException(status_code=500, detail="Не удалось сохранить аватар")

    current_user.avatar_url = f"/static/avatars/{filename}"
    current_user.updated_at = utcnow()
    db.commit()
    db.refresh(current_user)
    return current_user


@app.get("/user/search", response_model=List[UserOut], tags=["user"])
def search_users(q: str = Query(..., min_length=1), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = (
        db.query(User)
        .filter(User.username.ilike(f"%{q}%"), User.id != current_user.id)
        .limit(20)
        .all()
    )
    return users


# =========================================================================
# ЧАТЫ
# =========================================================================
@app.post("/chats", response_model=ChatOut, status_code=status.HTTP_201_CREATED, tags=["chats"])
def create_chat(data: ChatCreateIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if data.type == "private":
        if len(data.member_ids) != 1:
            raise HTTPException(status_code=400, detail="Для приватного чата нужен ровно один собеседник")
        other_id = data.member_ids[0]
        if is_blocked(db, other_id, current_user.id) or is_blocked(db, current_user.id, other_id):
            raise HTTPException(status_code=403, detail="Невозможно создать чат: пользователь заблокирован")

        # Проверка на существующий приватный чат между этими двумя пользователями
        existing = (
            db.query(Chat)
            .join(ChatMember, Chat.id == ChatMember.chat_id)
            .filter(Chat.type == "private", ChatMember.user_id.in_([current_user.id, other_id]))
            .group_by(Chat.id)
            .having(func.count(ChatMember.id) == 2)
            .first()
        )
        if existing:
            member = get_chat_member_or_404(db, existing.id, current_user.id)
            out = ChatOut.model_validate(existing)
            out.is_pinned = member.is_pinned
            out.folder = member.folder
            out.role = member.role
            return out

    if data.type in ("group", "channel") and not data.name:
        raise HTTPException(status_code=400, detail="Для группы/канала обязательно название")

    chat = Chat(
        type=data.type,
        name=data.name,
        description=data.description,
        avatar_url=data.avatar_url,
        created_by=current_user.id,
    )
    db.add(chat)
    db.flush()  # чтобы получить chat.id до коммита

    # Создатель — всегда creator
    db.add(ChatMember(chat_id=chat.id, user_id=current_user.id, role="creator"))

    # Остальные участники
    for member_id in data.member_ids:
        if member_id == current_user.id:
            continue
        user_exists = db.query(User).filter(User.id == member_id).first()
        if not user_exists:
            continue
        role = "member"
        db.add(ChatMember(chat_id=chat.id, user_id=member_id, role=role))

    db.commit()
    db.refresh(chat)

    out = ChatOut.model_validate(chat)
    out.role = "creator"
    logger.info("Создан чат id=%s type=%s пользователем %s", chat.id, chat.type, current_user.username)
    return out


@app.get("/chats", response_model=List[ChatOut], tags=["chats"])
def list_chats(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = (
        db.query(Chat, ChatMember)
        .join(ChatMember, Chat.id == ChatMember.chat_id)
        .filter(ChatMember.user_id == current_user.id)
        .order_by(ChatMember.is_pinned.desc(), Chat.created_at.desc())
    )
    rows = query.offset((page - 1) * limit).limit(limit).all()

    result = []
    for chat, member in rows:
        out = ChatOut.model_validate(chat)
        out.is_pinned = member.is_pinned
        out.folder = member.folder
        out.role = member.role
        result.append(out)
    return result


@app.get("/chats/{chat_id}", response_model=ChatOut, tags=["chats"])
def get_chat(chat_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    member = get_chat_member_or_404(db, chat_id, current_user.id)
    chat = db.query(Chat).filter(Chat.id == chat_id).first()
    if not chat:
        raise HTTPException(status_code=404, detail="Чат не найден")
    out = ChatOut.model_validate(chat)
    out.is_pinned = member.is_pinned
    out.folder = member.folder
    out.role = member.role
    return out


@app.delete("/chats/{chat_id}", tags=["chats"])
def delete_chat(chat_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    member = get_chat_member_or_404(db, chat_id, current_user.id)
    chat = db.query(Chat).filter(Chat.id == chat_id).first()
    if not chat:
        raise HTTPException(status_code=404, detail="Чат не найден")
    if member.role not in ("creator", "admin"):
        raise HTTPException(status_code=403, detail="Недостаточно прав для удаления чата")

    # Каскадное удаление сообщений и участников настроено в модели (cascade="all, delete-orphan")
    db.delete(chat)
    db.commit()
    logger.info("Чат id=%s удалён пользователем %s", chat_id, current_user.username)
    return {"detail": "Чат удалён"}


@app.post("/chats/{chat_id}/pin", tags=["chats"])
def toggle_pin(chat_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    member = get_chat_member_or_404(db, chat_id, current_user.id)
    member.is_pinned = not member.is_pinned
    db.commit()
    return {"is_pinned": member.is_pinned}


@app.put("/chats/{chat_id}/folder", tags=["chats"])
def set_folder(chat_id: int, data: FolderUpdateIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    member = get_chat_member_or_404(db, chat_id, current_user.id)
    member.folder = data.folder
    db.commit()
    return {"folder": member.folder}


@app.post("/chats/{chat_id}/members", tags=["chats"])
def add_member(chat_id: int, data: AddMemberIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    member = get_chat_member_or_404(db, chat_id, current_user.id)
    if member.role not in ("creator", "admin"):
        raise HTTPException(status_code=403, detail="Недостаточно прав для добавления участников")

    user_to_add = db.query(User).filter(User.id == data.user_id).first()
    if not user_to_add:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    exists = (
        db.query(ChatMember)
        .filter(ChatMember.chat_id == chat_id, ChatMember.user_id == data.user_id)
        .first()
    )
    if exists:
        raise HTTPException(status_code=400, detail="Пользователь уже в чате")

    db.add(ChatMember(chat_id=chat_id, user_id=data.user_id, role="member"))
    db.commit()
    return {"detail": "Участник добавлен"}


@app.delete("/chats/{chat_id}/members/{user_id}", tags=["chats"])
def remove_member(chat_id: int, user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    member = get_chat_member_or_404(db, chat_id, current_user.id)
    target = (
        db.query(ChatMember)
        .filter(ChatMember.chat_id == chat_id, ChatMember.user_id == user_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Участник не найден")

    # Пользователь может выйти сам, либо admin/creator может удалить другого
    if user_id != current_user.id and member.role not in ("creator", "admin"):
        raise HTTPException(status_code=403, detail="Недостаточно прав")

    db.delete(target)
    db.commit()
    return {"detail": "Участник удалён из чата"}


@app.put("/chats/{chat_id}/members/{user_id}/role", tags=["chats"])
def change_role(chat_id: int, user_id: int, data: RoleUpdateIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    member = get_chat_member_or_404(db, chat_id, current_user.id)
    if member.role != "creator":
        raise HTTPException(status_code=403, detail="Изменять роли может только создатель чата")

    target = (
        db.query(ChatMember)
        .filter(ChatMember.chat_id == chat_id, ChatMember.user_id == user_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Участник не найден")

    target.role = data.role
    db.commit()
    return {"detail": "Роль обновлена", "role": target.role}


# =========================================================================
# СООБЩЕНИЯ
# =========================================================================
@app.get("/chats/{chat_id}/messages", response_model=List[MessageOut], tags=["messages"])
def get_messages(
    chat_id: int,
    page: int = Query(1, ge=1),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    get_chat_member_or_404(db, chat_id, current_user.id)
    query = (
        db.query(Message)
        .filter(Message.chat_id == chat_id)
        .order_by(Message.created_at.desc())
        .offset((page - 1) * MESSAGES_PAGE_SIZE)
        .limit(MESSAGES_PAGE_SIZE)
    )
    messages = query.all()
    return list(reversed(messages))


@app.post("/chats/{chat_id}/messages", response_model=MessageOut, status_code=status.HTTP_201_CREATED, tags=["messages"])
def send_message_rest(
    chat_id: int,
    data: MessageCreateIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Отправка сообщения через REST (альтернатива WebSocket, например для файлов)."""
    get_chat_member_or_404(db, chat_id, current_user.id)

    # Проверка блокировки для приватных чатов
    chat = db.query(Chat).filter(Chat.id == chat_id).first()
    if chat and chat.type == "private":
        other_member = (
            db.query(ChatMember)
            .filter(ChatMember.chat_id == chat_id, ChatMember.user_id != current_user.id)
            .first()
        )
        if other_member and is_blocked(db, other_member.user_id, current_user.id):
            raise HTTPException(status_code=403, detail="Вы заблокированы этим пользователем")

    # Идемпотентность: если сообщение с таким message_id уже есть — вернуть его
    existing = db.query(Message).filter(Message.message_id == data.message_id).first()
    if existing:
        return existing

    message = Message(
        message_id=data.message_id,
        send_id=data.send_id,
        chat_id=chat_id,
        sender_id=current_user.id,
        content=data.content,
        file_url=data.file_url,
        file_type=data.file_type,
        file_name=data.file_name,
        delivered_at=utcnow(),
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message


@app.put("/messages/{message_id}/read", tags=["messages"])
def mark_message_read(message_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    message = db.query(Message).filter(Message.message_id == message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Сообщение не найдено")
    get_chat_member_or_404(db, message.chat_id, current_user.id)

    if not message.is_read:
        message.is_read = True
        message.read_at = utcnow()
        db.commit()
    return {"detail": "Сообщение отмечено прочитанным", "message_id": message.message_id}


@app.get("/messages/unread", tags=["messages"])
def get_unread_count(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    chat_ids = [m.chat_id for m in db.query(ChatMember).filter(ChatMember.user_id == current_user.id).all()]
    if not chat_ids:
        return {"total_unread": 0, "by_chat": {}}

    rows = (
        db.query(Message.chat_id, func.count(Message.id))
        .filter(
            Message.chat_id.in_(chat_ids),
            Message.sender_id != current_user.id,
            Message.is_read == False,  # noqa: E712
        )
        .group_by(Message.chat_id)
        .all()
    )
    by_chat = {chat_id: count for chat_id, count in rows}
    total = sum(by_chat.values())
    return {"total_unread": total, "by_chat": by_chat}


# =========================================================================
# ФАЙЛЫ
# =========================================================================
@app.post("/upload/temp", tags=["files"])
async def upload_temp_file(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    contents = await file.read()
    if len(contents) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(status_code=400, detail=f"Файл превышает лимит {MAX_FILE_SIZE_BYTES // 1024} КБ")

    file_type = "image" if (file.content_type or "").startswith("image/") else "document"
    ext = os.path.splitext(file.filename or "")[1]
    file_id = uuid.uuid4().hex
    filename = f"{file_id}{ext}"
    dest_path = os.path.join(UPLOAD_TEMP_DIR, filename)

    try:
        with open(dest_path, "wb") as out_file:
            out_file.write(contents)
    except Exception as exc:
        logger.error("Ошибка загрузки временного файла: %s", exc)
        raise HTTPException(status_code=500, detail="Не удалось сохранить файл")

    return {
        "file_id": filename,
        "file_url": f"/files/{filename}",
        "file_type": file_type,
        "file_name": file.filename,
        "expires_in_minutes": TEMP_FILE_TTL_MINUTES,
    }


@app.get("/files/{file_id}", tags=["files"])
def download_file(file_id: str, current_user: User = Depends(get_current_user)):
    file_path = os.path.join(UPLOAD_TEMP_DIR, file_id)
    # Защита от path traversal
    if not os.path.abspath(file_path).startswith(os.path.abspath(UPLOAD_TEMP_DIR)):
        raise HTTPException(status_code=400, detail="Некорректный идентификатор файла")
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Файл не найден или срок его хранения истёк")

    from fastapi.responses import FileResponse
    return FileResponse(file_path)


# =========================================================================
# БЛОКИРОВКИ
# =========================================================================
@app.post("/blocks/{user_id}", tags=["blocks"])
def block_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Нельзя заблокировать самого себя")
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    exists = (
        db.query(UserBlock)
        .filter(UserBlock.blocker_id == current_user.id, UserBlock.blocked_id == user_id)
        .first()
    )
    if exists:
        return {"detail": "Пользователь уже заблокирован"}

    db.add(UserBlock(blocker_id=current_user.id, blocked_id=user_id))
    db.commit()
    return {"detail": "Пользователь заблокирован"}


@app.delete("/blocks/{user_id}", tags=["blocks"])
def unblock_user(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    block = (
        db.query(UserBlock)
        .filter(UserBlock.blocker_id == current_user.id, UserBlock.blocked_id == user_id)
        .first()
    )
    if not block:
        raise HTTPException(status_code=404, detail="Блокировка не найдена")
    db.delete(block)
    db.commit()
    return {"detail": "Пользователь разблокирован"}


@app.get("/blocks", response_model=List[UserOut], tags=["blocks"])
def list_blocks(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    blocked_ids = [
        b.blocked_id
        for b in db.query(UserBlock).filter(UserBlock.blocker_id == current_user.id).all()
    ]
    if not blocked_ids:
        return []
    return db.query(User).filter(User.id.in_(blocked_ids)).all()


# =========================================================================
# КАНАЛЫ
# =========================================================================
@app.post("/channels/{chat_id}/subscribe", tags=["channels"])
def toggle_subscribe(chat_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    chat = db.query(Chat).filter(Chat.id == chat_id, Chat.type == "channel").first()
    if not chat:
        raise HTTPException(status_code=404, detail="Канал не найден")

    member = (
        db.query(ChatMember)
        .filter(ChatMember.chat_id == chat_id, ChatMember.user_id == current_user.id)
        .first()
    )
    if member:
        # Создатель не может отписаться от собственного канала
        if member.role == "creator":
            raise HTTPException(status_code=400, detail="Создатель не может отписаться от своего канала")
        db.delete(member)
        db.commit()
        return {"subscribed": False}
    else:
        db.add(ChatMember(chat_id=chat_id, user_id=current_user.id, role="member"))
        db.commit()
        return {"subscribed": True}


@app.get("/channels", response_model=List[ChatOut], tags=["channels"])
def list_public_channels(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    channels = (
        db.query(Chat)
        .filter(Chat.type == "channel")
        .order_by(Chat.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )
    return [ChatOut.model_validate(c) for c in channels]


# =========================================================================
# WEBSOCKET
# =========================================================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    """
    Основной WebSocket-канал для обмена сообщениями в реальном времени.
    Подключение: ws://.../ws?token=JWT
    """
    # Проверка JWT перед принятием соединения
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401)
        user_id = int(payload.get("sub"))
    except Exception:
        await websocket.close(code=4401)
        return

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            await websocket.close(code=4404)
            return

        await manager.connect(user_id, websocket)
        user.is_online = True
        user.last_seen = utcnow()
        db.commit()
        logger.info("Пользователь %s подключился по WebSocket", user.username)

        # Оповещаем всех участников чатов пользователя о том, что он онлайн
        chat_ids = [m.chat_id for m in db.query(ChatMember).filter(ChatMember.user_id == user_id).all()]
        for cid in chat_ids:
            await manager.broadcast_to_chat(
                db, cid, {"type": "status", "user_id": user_id, "is_online": True}, exclude_user_id=user_id
            )

        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")

            if msg_type == "message":
                await handle_ws_message(db, user, data)

            elif msg_type == "read":
                await handle_ws_read(db, user, data)

            elif msg_type == "delivered":
                await handle_ws_delivered(db, data)

            else:
                logger.warning("Неизвестный тип WebSocket-сообщения: %s", msg_type)

    except WebSocketDisconnect:
        logger.info("Пользователь id=%s отключился от WebSocket", user_id)
    except Exception as exc:
        logger.error("Ошибка WebSocket для пользователя id=%s: %s", user_id, exc)
    finally:
        manager.disconnect(user_id, websocket)
        # Если у пользователя больше нет активных соединений — помечаем офлайн
        if not manager.is_online(user_id):
            user_db = db.query(User).filter(User.id == user_id).first()
            if user_db:
                user_db.is_online = False
                user_db.last_seen = utcnow()
                db.commit()
                chat_ids = [m.chat_id for m in db.query(ChatMember).filter(ChatMember.user_id == user_id).all()]
                for cid in chat_ids:
                    await manager.broadcast_to_chat(
                        db, cid, {"type": "status", "user_id": user_id, "is_online": False}, exclude_user_id=user_id
                    )
        db.close()


async def handle_ws_message(db: Session, sender: User, data: dict):
    """Обработка входящего сообщения от клиента: сохранение в БД + рассылка участникам чата."""
    chat_id = data.get("chat_id")
    message_id = data.get("message_id")
    send_id = data.get("send_id")
    content = data.get("content")

    if not all([chat_id, message_id, send_id, content]):
        logger.warning("Некорректный формат сообщения от пользователя %s", sender.username)
        return

    member = db.query(ChatMember).filter(ChatMember.chat_id == chat_id, ChatMember.user_id == sender.id).first()
    if not member:
        await manager.send_to_user(sender.id, {"type": "error", "detail": "Вы не участник этого чата"})
        return

    # Проверка блокировки в приватных чатах
    chat = db.query(Chat).filter(Chat.id == chat_id).first()
    if chat and chat.type == "private":
        other_member = (
            db.query(ChatMember)
            .filter(ChatMember.chat_id == chat_id, ChatMember.user_id != sender.id)
            .first()
        )
        if other_member and is_blocked(db, other_member.user_id, sender.id):
            await manager.send_to_user(sender.id, {"type": "error", "detail": "Вы заблокированы этим пользователем"})
            return

    # Идемпотентность по message_id
    existing = db.query(Message).filter(Message.message_id == message_id).first()
    if existing:
        message = existing
    else:
        message = Message(
            message_id=message_id,
            send_id=send_id,
            chat_id=chat_id,
            sender_id=sender.id,
            content=content,
            file_url=data.get("file_url"),
            file_type=data.get("file_type"),
            file_name=data.get("file_name"),
            delivered_at=utcnow(),
        )
        db.add(message)
        db.commit()
        db.refresh(message)

    outgoing = {
        "type": "message",
        "message_id": message.message_id,
        "send_id": message.send_id,
        "sender_id": message.sender_id,
        "chat_id": message.chat_id,
        "content": message.content,
        "file_url": message.file_url,
        "file_type": message.file_type,
        "file_name": message.file_name,
        "created_at": message.created_at.isoformat(),
    }
    # Рассылаем всем участникам чата, кроме отправителя
    await manager.broadcast_to_chat(db, chat_id, outgoing, exclude_user_id=sender.id)

    # Подтверждение доставки отправителю
    await manager.send_to_user(
        sender.id,
        {"type": "delivered", "message_id": message.message_id, "send_id": message.send_id},
    )


async def handle_ws_read(db: Session, reader: User, data: dict):
    """Обработка отметки о прочтении сообщения — уведомляет отправителя."""
    message_id = data.get("message_id")
    message = db.query(Message).filter(Message.message_id == message_id).first()
    if not message:
        return

    member = db.query(ChatMember).filter(ChatMember.chat_id == message.chat_id, ChatMember.user_id == reader.id).first()
    if not member:
        return

    if not message.is_read:
        message.is_read = True
        message.read_at = utcnow()
        db.commit()

    await manager.send_to_user(
        message.sender_id,
        {"type": "read", "message_id": message.message_id, "send_id": message.send_id},
    )


async def handle_ws_delivered(db: Session, data: dict):
    """Обработка явного подтверждения доставки от клиента (если клиент присылает его сам)."""
    message_id = data.get("message_id")
    message = db.query(Message).filter(Message.message_id == message_id).first()
    if not message:
        return
    if not message.delivered_at:
        message.delivered_at = utcnow()
        db.commit()
    await manager.send_to_user(
        message.sender_id,
        {"type": "delivered", "message_id": message.message_id, "send_id": message.send_id},
    )


# =========================================================================
# СЛУЖЕБНЫЕ ЭНДПОИНТЫ
# =========================================================================
@app.get("/", tags=["health"])
def health_check():
    return {"status": "ok", "service": "ARTMessage API", "time": utcnow().isoformat()}


# =========================================================================
# ТОЧКА ВХОДА
# =========================================================================
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
