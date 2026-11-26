import calendar
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import os
import secrets
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import psycopg2
from pydantic import BaseModel, Field

# ==========================================
# 設定・定数
# ==========================================
TOKEN_TTL_DAYS = 14
DEFAULT_WALLET_NAMES = ["現金", "PayPay", "三井住友", "その他"]
AUTO_SUB_MEMO_PREFIX = "自動サブスク引き落とし:"

app = FastAPI(title="サブスク・固定費＆おこづかい帳API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# Pydantic モデル
# ==========================================
class CategoryEnum(str, Enum):
    entertainment = "エンタメ"
    music = "音楽"
    game = "ゲーム"
    communication = "通信"
    infrastructure = "通信・インフラ"
    housing = "住まい"
    shopping = "生活・ショッピング"
    work_study = "仕事・学習"
    other = "その他"


class AuthRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=4, max_length=128)


class SubscriptionCreate(BaseModel):
    name: str
    price: int
    billing_day: int
    started_from: Optional[date] = None
    categories: List[CategoryEnum]
    payment_method: str


class SubscriptionUpdate(BaseModel):
    name: str
    price: Optional[int] = None
    billing_day: Optional[int] = None
    started_from: Optional[date] = None
    categories: Optional[List[CategoryEnum]] = None
    payment_method: Optional[str] = None


class PriceChangeCreate(BaseModel):
    price: int
    effective_from: date


class PauseCreate(BaseModel):
    pause_from: date
    pause_until: Optional[date] = None


class PocketEntryCreate(BaseModel):
    entry_type: str  # "income" | "expense"
    amount: int
    entry_date: date
    title: str
    category: str = "その他"
    payment_method: str = "現金"
    memo: str = ""


class PocketEntryUpdate(BaseModel):
    entry_type: str
    amount: int = Field(..., ge=0)
    entry_date: date
    title: str = Field(..., min_length=1, max_length=120)
    category: str = "その他"
    payment_method: str = "現金"
    memo: str = ""


class PocketEntrySplit(BaseModel):
    split_amount: int = Field(..., gt=0)
    title: str = Field(..., min_length=1, max_length=120)
    category: str = "その他"
    entry_date: Optional[date] = None
    payment_method: Optional[str] = None
    memo: str = ""


class WalletBalanceUpdate(BaseModel):
    wallet_id: Optional[int] = None
    wallet_name: Optional[str] = None
    target_balance: int
    note: str = "残高調整"


class WalletCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=60)
    balance: int = 0


class WalletRename(BaseModel):
    name: str = Field(..., min_length=1, max_length=60)


class WalletTransfer(BaseModel):
    from_wallet_id: int
    to_wallet_id: int
    amount: int = Field(..., gt=0)
    memo: str = ""


# ==========================================
# DB接続・トランザクション管理
# ==========================================
def get_db_connection():
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        return psycopg2.connect(database_url)
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "db"),
        database=os.getenv("DB_NAME", "mydb"),
        user=os.getenv("DB_USER", "myuser"),
        password=os.getenv("DB_PASSWORD", "mypassword"),
        port=os.getenv("DB_PORT", "5432"),
    )


@contextmanager
def db_session():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def db_cursor():
    with db_session() as cur:
        yield cur


# ==========================================
# 認証・セキュリティ
# ==========================================
def hash_password(password: str, salt: Optional[str] = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, expected = stored_hash.split("$", 1)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000).hex()
    return hmac.compare_digest(actual, expected)


def get_current_user(authorization: Optional[str] = Header(default=None), cur=Depends(db_cursor)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="ログインが必要です。")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="認証トークンが空です。")

    cur.execute(
        """
        SELECT s.token, s.expires_at, u.id, u.username
        FROM auth_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = %s;
        """,
        (token,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="セッションが無効です。再度ログインしてください。")

    expires_at = row[1]
    if isinstance(expires_at, datetime):
        exp_utc = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
    else:
        exp_utc = datetime.fromisoformat(str(expires_at)).replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > exp_utc:
        cur.execute("DELETE FROM auth_sessions WHERE token = %s;", (token,))
        raise HTTPException(status_code=401, detail="セッションの有効期限が切れました。再度ログインしてください。")

    return {"token": row[0], "user_id": int(row[2]), "username": row[3]}


# ==========================================
# ヘルパー関数
# ==========================================
def ensure_default_wallets(cur, user_id: int):
    cur.execute("SELECT COUNT(*) FROM wallet_accounts WHERE user_id = %s;", (user_id,))
    if int(cur.fetchone()[0] or 0) == 0:
        for idx, wname in enumerate(DEFAULT_WALLET_NAMES):
            cur.execute(
                """
                INSERT INTO wallet_accounts (user_id, name, balance, is_default, sort_order)
                VALUES (%s, %s, 0, TRUE, %s)
                ON CONFLICT (user_id, name) DO NOTHING;
                """,
                (user_id, wname, idx),
            )


def get_or_create_wallet_by_name(cur, user_id: int, name: str) -> int:
    clean = (name or "").strip() or "その他"
    cur.execute("SELECT id FROM wallet_accounts WHERE user_id = %s AND name = %s;", (user_id, clean))
    row = cur.fetchone()
    if row:
        return int(row[0])
    cur.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM wallet_accounts WHERE user_id = %s;", (user_id,))
    next_order = int(cur.fetchone()[0] or 1)
    cur.execute(
        """
        INSERT INTO wallet_accounts (user_id, name, balance, is_default, sort_order)
        VALUES (%s, %s, 0, FALSE, %s) RETURNING id;
        """,
        (user_id, clean, next_order),
    )
    return int(cur.fetchone()[0])


def calculate_pocket_balances_by_method(cur, user_id: int) -> dict:
    cur.execute(
        """
        SELECT payment_method, entry_type, COALESCE(SUM(amount), 0)
        FROM pocket_entries
        WHERE user_id = %s
        GROUP BY payment_method, entry_type;
        """,
        (user_id,),
    )
    totals = {}
    for method_raw, entry_type, amt_sum in cur.fetchall():
        method_name = (method_raw or "").strip() or "その他"
        val = int(amt_sum or 0)
        totals[method_name] = totals.get(method_name, 0) + (val if entry_type == "income" else -val)
    return totals


def get_wallet_summary(cur, user_id: int) -> dict:
    ensure_default_wallets(cur, user_id)
    pocket_totals = calculate_pocket_balances_by_method(cur, user_id)
    cur.execute(
        "SELECT id, name, is_default FROM wallet_accounts WHERE user_id = %s ORDER BY sort_order ASC, id ASC;",
        (user_id,),
    )
    rows = cur.fetchall()
    seen_names = set()
    wallets = []
    for r in rows:
        wname = r[1]
        seen_names.add(wname)
        wallets.append({"id": int(r[0]), "name": wname, "balance": int(pocket_totals.get(wname, 0)), "is_default": bool(r[2])})

    for extra_name, extra_bal in pocket_totals.items():
        if extra_name not in seen_names:
            wallets.append({"id": -1, "name": extra_name, "balance": int(extra_bal), "is_default": False})

    return {"current_balance": sum(int(w["balance"] or 0) for w in wallets), "wallets": wallets}


def get_billing_date_obj(year: int, month: int, billing_day: int) -> date:
    last_day = calendar.monthrange(year, month)[1]
    return date(year, month, max(1, min(billing_day, last_day)))


def is_started_on_date(started_from: Optional[date], target_date: date) -> bool:
    return True if started_from is None else started_from <= target_date


def get_price_for_date(cur, sub_id: int, target_date: date, fallback_price: int) -> int:
    cur.execute(
        """
        SELECT price FROM subscription_price_history
        WHERE subscription_id = %s AND effective_from <= %s
        ORDER BY effective_from DESC, id DESC LIMIT 1;
        """,
        (sub_id, target_date),
    )
    row = cur.fetchone()
    return row[0] if row is not None else fallback_price


def is_paused_on_date(cur, sub_id: int, target_date: date) -> bool:
    cur.execute(
        """
        SELECT 1 FROM subscription_pauses
        WHERE subscription_id = %s AND pause_from <= %s AND (pause_until IS NULL OR %s <= pause_until)
        LIMIT 1;
        """,
        (sub_id, target_date, target_date),
    )
    return cur.fetchone() is not None


def sync_current_subscription_price(cur, sub_id: int, user_id: int):
    cur.execute("SELECT price FROM subscriptions WHERE id = %s AND user_id = %s;", (sub_id, user_id))
    sub_row = cur.fetchone()
    if sub_row:
        latest = get_price_for_date(cur, sub_id, date.today(), sub_row[0])
        cur.execute("UPDATE subscriptions SET price = %s WHERE id = %s AND user_id = %s;", (latest, sub_id, user_id))


def get_owned_subscription(cur, sub_id: int, user_id: int):
    cur.execute(
        "SELECT id, name, price, billing_day, categories, payment_method, started_from FROM subscriptions WHERE id = %s AND user_id = %s;",
        (sub_id, user_id),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="指定したサブスクが見つかりませんでした")
    return row


def format_pocket_entry(r):
    return {
        "id": r[0],
        "entry_type": r[1],
        "amount": r[2],
        "entry_date": r[3].isoformat() if hasattr(r[3], "isoformat") else str(r[3]),
        "title": r[4],
        "category": r[5],
        "payment_method": r[6] or "その他",
        "memo": r[7] or "",
    }


# ==========================================
# 起動時初期化（テーブル自動生成）
# ==========================================
@app.on_event("startup")
def startup_event():
    with db_session() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS auth_sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL DEFAULT 1,
                name VARCHAR(100) NOT NULL,
                price INTEGER NOT NULL,
                billing_day INTEGER NOT NULL,
                started_from DATE,
                categories TEXT[] NOT NULL,
                payment_method VARCHAR(50) NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscription_price_history (
                id SERIAL PRIMARY KEY,
                subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
                price INTEGER NOT NULL,
                effective_from DATE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscription_pauses (
                id SERIAL PRIMARY KEY,
                subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
                pause_from DATE NOT NULL,
                pause_until DATE
            );
            CREATE TABLE IF NOT EXISTS pocket_entries (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL DEFAULT 1,
                entry_type VARCHAR(16) NOT NULL CHECK (entry_type IN ('income', 'expense')),
                amount INTEGER NOT NULL CHECK (amount >= 0),
                entry_date DATE NOT NULL,
                title VARCHAR(120) NOT NULL,
                category VARCHAR(60) NOT NULL DEFAULT 'その他',
                payment_method VARCHAR(60) NOT NULL DEFAULT 'その他',
                memo TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS subscription_bill_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
                billing_date DATE NOT NULL,
                amount INTEGER NOT NULL,
                payment_method VARCHAR(60) NOT NULL DEFAULT 'その他',
                pocket_entry_id INTEGER,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (user_id, subscription_id, billing_date)
            );
            CREATE TABLE IF NOT EXISTS wallet_accounts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(60) NOT NULL,
                balance INTEGER NOT NULL DEFAULT 0,
                is_default BOOLEAN NOT NULL DEFAULT FALSE,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (user_id, name)
            );
        """)
        cur.execute("SELECT id FROM users LIMIT 1;")
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id;",
                ("default_user", hash_password("changeme123")),
            )
        cur.execute("SELECT id FROM users;")
        for (uid,) in cur.fetchall():
            ensure_default_wallets(cur, uid)


# ==========================================
# ルーティング: トップ画面 & 認証
# ==========================================
@app.get("/")
def serve_index():
    return FileResponse("index.html")


@app.post("/auth/register")
def register_user(payload: AuthRequest, cur=Depends(db_cursor)):
    username = payload.username.strip()
    if len(username) < 2:
        raise HTTPException(status_code=400, detail="ユーザー名は2文字以上で入力してください。")

    cur.execute("SELECT id FROM users WHERE username = %s;", (username,))
    if cur.fetchone():
        raise HTTPException(status_code=409, detail="そのユーザー名はすでに登録されています。")

    pw_hash = hash_password(payload.password)
    cur.execute(
        "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id, username;",
        (username, pw_hash),
    )
    user_id, uname = cur.fetchone()
    ensure_default_wallets(cur, user_id)

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=TOKEN_TTL_DAYS)
    cur.execute(
        "INSERT INTO auth_sessions (token, user_id, expires_at) VALUES (%s, %s, %s);",
        (token, user_id, expires_at.replace(tzinfo=None)),
    )
    return {"token": token, "user_id": user_id, "username": uname}


@app.post("/auth/login")
def login_user(payload: AuthRequest, cur=Depends(db_cursor)):
    username = payload.username.strip()
    cur.execute("SELECT id, username, password_hash FROM users WHERE username = %s;", (username,))
    row = cur.fetchone()
    if not row or not verify_password(payload.password, row[2]):
        raise HTTPException(status_code=401, detail="ユーザー名またはパスワードが正しくありません。")

    user_id = int(row[0])
    ensure_default_wallets(cur, user_id)
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=TOKEN_TTL_DAYS)
    cur.execute(
        "INSERT INTO auth_sessions (token, user_id, expires_at) VALUES (%s, %s, %s);",
        (token, user_id, expires_at.replace(tzinfo=None)),
    )
    return {"token": token, "user_id": user_id, "username": row[1]}


@app.post("/auth/logout")
def logout_user(current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    cur.execute("DELETE FROM auth_sessions WHERE token = %s;", (current_user["token"],))
    return {"status": "success"}


@app.get("/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {"user_id": current_user["user_id"], "username": current_user["username"]}


# ==========================================
# ルーティング: ウォレット・口座管理
# ==========================================
@app.get("/wallet/balance")
def get_wallet_balance(current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    return get_wallet_summary(cur, current_user["user_id"])


@app.put("/wallet/balance")
def set_wallet_balance(payload: WalletBalanceUpdate, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    target_wallet_id = payload.wallet_id
    if target_wallet_id is None:
        target_wallet_id = get_or_create_wallet_by_name(cur, uid, (payload.wallet_name or "").strip() or "現金")

    cur.execute("SELECT id, name FROM wallet_accounts WHERE id = %s AND user_id = %s;", (target_wallet_id, uid))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="指定した口座・手段が見つかりませんでした。")

    wallet_name = row[1]
    pocket_totals = calculate_pocket_balances_by_method(cur, uid)
    old_balance = int(pocket_totals.get(wallet_name, 0))
    new_balance = int(payload.target_balance)
    diff = new_balance - old_balance

    auto_entry = None
    clean_note = (payload.note or "").strip()
    if diff != 0:
        etype = "income" if diff > 0 else "expense"
        ecat = "雑所得" if diff > 0 else "雑損益"
        title = clean_note or f"残高調整（{ecat}/{wallet_name}）"
        cur.execute(
            """
            INSERT INTO pocket_entries (user_id, entry_type, amount, entry_date, title, category, payment_method, memo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, entry_type, amount, entry_date, title, category, payment_method, memo;
            """,
            (uid, etype, abs(diff), date.today(), title[:120], ecat, wallet_name, f"残高修正: {old_balance}円 → {new_balance}円"),
        )
        auto_entry = format_pocket_entry(cur.fetchone())

    data = get_wallet_summary(cur, uid)
    return {
        "status": "success",
        "wallet_id": int(row[0]),
        "wallet_name": wallet_name,
        "adjustment_added": diff,
        "note": clean_note or "残高調整",
        "auto_entry": auto_entry,
        **data,
    }


@app.post("/wallets")
def create_wallet(payload: WalletCreate, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    clean_name = payload.name.strip()
    if not clean_name:
        raise HTTPException(status_code=400, detail="項目名を入力してください。")

    cur.execute("SELECT id FROM wallet_accounts WHERE user_id = %s AND name = %s;", (uid, clean_name))
    if cur.fetchone():
        raise HTTPException(status_code=409, detail=f"「{clean_name}」はすでに登録されています。")

    cur.execute("SELECT COALESCE(MAX(sort_order), 0) + 1 FROM wallet_accounts WHERE user_id = %s;", (uid,))
    next_order = int(cur.fetchone()[0] or 1)
    cur.execute(
        """
        INSERT INTO wallet_accounts (user_id, name, balance, is_default, sort_order)
        VALUES (%s, %s, 0, FALSE, %s) RETURNING id, name, is_default;
        """,
        (uid, clean_name, next_order),
    )
    created = cur.fetchone()

    init_bal = int(payload.balance or 0)
    if init_bal != 0:
        etype = "income" if init_bal > 0 else "expense"
        ecat = "雑所得" if init_bal > 0 else "雑損益"
        cur.execute(
            """
            INSERT INTO pocket_entries (user_id, entry_type, amount, entry_date, title, category, payment_method, memo)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (uid, etype, abs(init_bal), date.today(), f"初期残高（{clean_name}）"[:120], ecat, clean_name, "口座追加時の初期残高"),
        )

    summary = get_wallet_summary(cur, uid)
    matched = next((w for w in summary["wallets"] if w["name"] == clean_name), None)
    return {
        "status": "success",
        "wallet": {
            "id": int(created[0]),
            "name": created[1],
            "balance": int(matched["balance"] if matched else 0),
            "is_default": bool(created[2]),
        },
        **summary,
    }


@app.put("/wallets/{wallet_id}")
def rename_wallet(wallet_id: int, payload: WalletRename, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    new_name = payload.name.strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="新しい項目名を入力してください。")

    cur.execute("SELECT id, name FROM wallet_accounts WHERE id = %s AND user_id = %s;", (wallet_id, uid))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="対象の項目が見つかりませんでした。")

    old_name = row[1]
    if old_name != new_name:
        cur.execute("SELECT id FROM wallet_accounts WHERE user_id = %s AND name = %s AND id != %s;", (uid, new_name, wallet_id))
        if cur.fetchone():
            raise HTTPException(status_code=409, detail=f"「{new_name}」はすでに存在します。")

        cur.execute("UPDATE wallet_accounts SET name = %s WHERE id = %s AND user_id = %s;", (new_name, wallet_id, uid))
        cur.execute("UPDATE pocket_entries SET payment_method = %s WHERE user_id = %s AND payment_method = %s;", (new_name, uid, old_name))
        cur.execute("UPDATE subscriptions SET payment_method = %s WHERE user_id = %s AND payment_method = %s;", (new_name, uid, old_name))

    summary = get_wallet_summary(cur, uid)
    return {"status": "success", "old_name": old_name, "new_name": new_name, **summary}


@app.delete("/wallets/{wallet_id}")
def delete_wallet(wallet_id: int, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    cur.execute("SELECT id, name, is_default FROM wallet_accounts WHERE id = %s AND user_id = %s;", (wallet_id, uid))
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="対象の項目が見つかりませんでした。")
    if bool(row[2]):
        raise HTTPException(status_code=400, detail="初期項目（現金・PayPay・三井住友・その他）は削除できません。名称変更や残高修正をご利用ください。")

    cur.execute("DELETE FROM wallet_accounts WHERE id = %s AND user_id = %s;", (wallet_id, uid))
    summary = get_wallet_summary(cur, uid)
    return {"status": "success", "deleted_id": wallet_id, **summary}


@app.post("/wallets/transfer")
def transfer_wallet_balance(payload: WalletTransfer, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    if payload.from_wallet_id == payload.to_wallet_id:
        raise HTTPException(status_code=400, detail="移動元と移動先には別の口座・手段を選んでください。")

    cur.execute("SELECT id, name FROM wallet_accounts WHERE id = %s AND user_id = %s;", (payload.from_wallet_id, uid))
    from_row = cur.fetchone()
    cur.execute("SELECT id, name FROM wallet_accounts WHERE id = %s AND user_id = %s;", (payload.to_wallet_id, uid))
    to_row = cur.fetchone()

    if not from_row or not to_row:
        raise HTTPException(status_code=404, detail="移動元または移動先の口座が見つかりませんでした。")

    from_name, to_name = from_row[1], to_row[1]
    amt = int(payload.amount)
    clean_memo = payload.memo.strip()
    today_dt = date.today()

    cur.execute(
        """
        INSERT INTO pocket_entries (user_id, entry_type, amount, entry_date, title, category, payment_method, memo)
        VALUES (%s, 'expense', %s, %s, %s, %s, %s, %s);
        """,
        (uid, amt, today_dt, f"{from_name}→{to_name}へ移動"[:120], "その他", from_name, clean_memo or f"{to_name}へ移動"),
    )
    cur.execute(
        """
        INSERT INTO pocket_entries (user_id, entry_type, amount, entry_date, title, category, payment_method, memo)
        VALUES (%s, 'income', %s, %s, %s, %s, %s, %s);
        """,
        (uid, amt, today_dt, f"{from_name}から{to_name}へ移動"[:120], "その他", to_name, clean_memo or f"{from_name}から移動"),
    )

    summary = get_wallet_summary(cur, uid)
    return {"status": "success", "from_name": from_name, "to_name": to_name, "amount": amt, "memo": clean_memo, **summary}


# ==========================================
# ルーティング: サブスク・固定費管理
# ==========================================
@app.get("/subscriptions")
def get_subscriptions(current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    cur.execute(
        "SELECT id, name, price, billing_day, categories, payment_method, started_from FROM subscriptions WHERE user_id = %s ORDER BY id;",
        (uid,),
    )
    rows = cur.fetchall()
    today = date.today()
    return [
        {
            "id": r[0],
            "name": r[1],
            "price": get_price_for_date(cur, r[0], today, r[2]),
            "billing_day": r[3],
            "categories": r[4],
            "payment_method": r[5],
            "started_from": r[6].isoformat() if r[6] else None,
            "is_paused_today": is_paused_on_date(cur, r[0], today),
        }
        for r in rows
    ]


@app.put("/subscriptions/{sub_id}")
def update_subscription(sub_id: int, payload: SubscriptionUpdate, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    current = get_owned_subscription(cur, sub_id, uid)

    next_name = payload.name.strip() if payload.name and payload.name.strip() else current[1]
    next_price = payload.price if payload.price is not None else current[2]
    next_billing_day = payload.billing_day if payload.billing_day is not None else current[3]
    next_categories = payload.categories if payload.categories is not None else current[4]
    next_payment_method = (
        payload.payment_method.strip() if payload.payment_method is not None and payload.payment_method.strip() else current[5]
    )
    next_started_from = payload.started_from if payload.started_from is not None else current[6]

    cur.execute(
        """
        UPDATE subscriptions
        SET name = %s, price = %s, billing_day = %s, categories = %s, payment_method = %s, started_from = %s
        WHERE id = %s AND user_id = %s
        RETURNING id, name, price, billing_day, categories, payment_method, started_from;
        """,
        (next_name, next_price, next_billing_day, next_categories, next_payment_method, next_started_from, sub_id, uid),
    )
    updated = cur.fetchone()
    return {
        "status": "success",
        "subscription": {
            "id": updated[0],
            "name": updated[1],
            "price": updated[2],
            "billing_day": updated[3],
            "categories": updated[4],
            "payment_method": updated[5],
            "started_from": updated[6].isoformat() if updated[6] else None,
        },
    }


@app.get("/subscriptions/total")
def get_subscriptions_total(current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    cur.execute("SELECT id, price, started_from FROM subscriptions WHERE user_id = %s;", (uid,))
    rows = cur.fetchall()
    today = date.today()
    total_price = 0
    active_count = 0
    for r in rows:
        if not is_started_on_date(r[2], today):
            continue
        if not is_paused_on_date(cur, r[0], today):
            total_price += get_price_for_date(cur, r[0], today, r[1])
            active_count += 1
    return {"total_monthly_price": total_price, "registered_count": active_count, "currency": "JPY"}


@app.get("/subscriptions/monthly")
def get_monthly_subscriptions(
    year: int = Query(..., ge=2000, le=2100),
    month: int = Query(..., ge=1, le=12),
    current_user: dict = Depends(get_current_user),
    cur=Depends(db_cursor),
):
    uid = current_user["user_id"]
    cur.execute(
        "SELECT id, name, price, billing_day, categories, payment_method, started_from FROM subscriptions WHERE user_id = %s ORDER BY billing_day ASC, id ASC;",
        (uid,),
    )
    rows = cur.fetchall()

    items, paused_items = [], []
    total_price = 0

    for r in rows:
        billing_dt = get_billing_date_obj(year, month, r[3])
        if not is_started_on_date(r[6], billing_dt):
            continue

        price = get_price_for_date(cur, r[0], billing_dt, r[2])
        paused = is_paused_on_date(cur, r[0], billing_dt)

        cur.execute(
            "SELECT 1 FROM subscription_bill_logs WHERE user_id = %s AND subscription_id = %s AND billing_date = %s;",
            (uid, r[0], billing_dt),
        )
        already_billed = cur.fetchone() is not None

        entry = {
            "id": r[0],
            "name": r[1],
            "price": price,
            "billing_day": r[3],
            "billing_date": billing_dt.isoformat(),
            "categories": r[4],
            "payment_method": r[5],
            "started_from": r[6].isoformat() if r[6] else None,
            "is_paused": paused,
            "already_billed": already_billed,
        }

        if paused:
            paused_items.append(entry)
        else:
            total_price += price
            items.append(entry)

    return {
        "year": year,
        "month": month,
        "total_monthly_price": total_price,
        "count": len(items),
        "items": items,
        "paused_items": paused_items,
    }


@app.get("/subscriptions/annual")
def get_annual_subscriptions(
    year: int = Query(..., ge=2000, le=2100),
    current_user: dict = Depends(get_current_user),
    cur=Depends(db_cursor),
):
    uid = current_user["user_id"]
    cur.execute(
        "SELECT id, name, price, billing_day, categories, payment_method, started_from FROM subscriptions WHERE user_id = %s ORDER BY billing_day ASC, id ASC;",
        (uid,),
    )
    rows = cur.fetchall()

    months_data = []
    annual_total = 0

    for m in range(1, 13):
        month_total = 0
        schedules = []
        for r in rows:
            billing_dt = get_billing_date_obj(year, m, r[3])
            if not is_started_on_date(r[6], billing_dt) or is_paused_on_date(cur, r[0], billing_dt):
                continue
            price = get_price_for_date(cur, r[0], billing_dt, r[2])
            month_total += price
            schedules.append({"id": r[0], "name": r[1], "price": price, "billing_date": billing_dt.isoformat(), "payment_method": r[5]})
        annual_total += month_total
        months_data.append({"month": m, "total_price": month_total, "schedules": schedules})

    return {"year": year, "annual_total_price": annual_total, "months": months_data}


@app.post("/subscriptions")
def create_subscription(sub: SubscriptionCreate, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    effective_start = sub.started_from or date.today()
    cur.execute(
        """
        INSERT INTO subscriptions (user_id, name, price, billing_day, started_from, categories, payment_method)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id, name, price, billing_day, categories, payment_method, started_from;
        """,
        (uid, sub.name, sub.price, sub.billing_day, effective_start, sub.categories, sub.payment_method),
    )
    new_sub = cur.fetchone()
    cur.execute(
        "INSERT INTO subscription_price_history (subscription_id, price, effective_from) VALUES (%s, %s, %s);",
        (new_sub[0], new_sub[2], effective_start),
    )
    return {
        "status": "success",
        "subscription": {
            "id": new_sub[0],
            "name": new_sub[1],
            "price": new_sub[2],
            "billing_day": new_sub[3],
            "categories": new_sub[4],
            "payment_method": new_sub[5],
            "started_from": new_sub[6].isoformat() if new_sub[6] else None,
        },
    }


@app.post("/subscriptions/{sub_id}/price-changes")
def add_price_change(sub_id: int, change: PriceChangeCreate, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    get_owned_subscription(cur, sub_id, uid)
    cur.execute(
        "INSERT INTO subscription_price_history (subscription_id, price, effective_from) VALUES (%s, %s, %s) RETURNING id, subscription_id, price, effective_from;",
        (sub_id, change.price, change.effective_from),
    )
    created = cur.fetchone()
    sync_current_subscription_price(cur, sub_id, uid)
    return {
        "status": "success",
        "price_change": {
            "id": created[0],
            "subscription_id": created[1],
            "price": created[2],
            "effective_from": created[3].isoformat(),
        },
    }


@app.get("/subscriptions/{sub_id}/price-changes")
def get_price_changes(sub_id: int, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    get_owned_subscription(cur, sub_id, uid)
    cur.execute(
        "SELECT id, subscription_id, price, effective_from FROM subscription_price_history WHERE subscription_id = %s ORDER BY effective_from ASC, id ASC;",
        (sub_id,),
    )
    return [
        {"id": r[0], "subscription_id": r[1], "price": r[2], "effective_from": r[3].isoformat()}
        for r in cur.fetchall()
    ]


@app.delete("/subscriptions/{sub_id}/price-changes/{change_id}")
def delete_price_change(sub_id: int, change_id: int, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    get_owned_subscription(cur, sub_id, uid)
    cur.execute(
        "DELETE FROM subscription_price_history WHERE id = %s AND subscription_id = %s RETURNING id;",
        (change_id, sub_id),
    )
    deleted = cur.fetchone()
    if not deleted:
        raise HTTPException(status_code=404, detail="指定した料金改定履歴が見つかりませんでした")
    sync_current_subscription_price(cur, sub_id, uid)
    return {"status": "success", "deleted_change_id": deleted[0]}


@app.get("/subscriptions/{sub_id}/pauses")
def get_pauses(sub_id: int, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    get_owned_subscription(cur, sub_id, uid)
    cur.execute(
        "SELECT id, subscription_id, pause_from, pause_until FROM subscription_pauses WHERE subscription_id = %s ORDER BY pause_from ASC, id ASC;",
        (sub_id,),
    )
    return [
        {"id": r[0], "subscription_id": r[1], "pause_from": r[2].isoformat(), "pause_until": r[3].isoformat() if r[3] else None}
        for r in cur.fetchall()
    ]


@app.post("/subscriptions/{sub_id}/pauses")
def add_pause(sub_id: int, payload: PauseCreate, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    if payload.pause_until is not None and payload.pause_until < payload.pause_from:
        raise HTTPException(status_code=400, detail="停止終了日は停止開始日以降の日付を指定してください")
    uid = current_user["user_id"]
    get_owned_subscription(cur, sub_id, uid)
    cur.execute(
        "INSERT INTO subscription_pauses (subscription_id, pause_from, pause_until) VALUES (%s, %s, %s) RETURNING id, subscription_id, pause_from, pause_until;",
        (sub_id, payload.pause_from, payload.pause_until),
    )
    created = cur.fetchone()
    return {
        "status": "success",
        "pause": {
            "id": created[0],
            "subscription_id": created[1],
            "pause_from": created[2].isoformat(),
            "pause_until": created[3].isoformat() if created[3] else None,
        },
    }


@app.delete("/subscriptions/{sub_id}/pauses/{pause_id}")
def delete_pause(sub_id: int, pause_id: int, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    get_owned_subscription(cur, sub_id, uid)
    cur.execute("DELETE FROM subscription_pauses WHERE id = %s AND subscription_id = %s RETURNING id;", (pause_id, sub_id))
    deleted = cur.fetchone()
    if not deleted:
        raise HTTPException(status_code=404, detail="指定した停止期間が見つかりませんでした")
    return {"status": "success", "deleted_pause_id": deleted[0]}


@app.delete("/subscriptions/{sub_id}")
def delete_subscription(sub_id: int, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    get_owned_subscription(cur, sub_id, uid)

    cur.execute("SELECT pocket_entry_id FROM subscription_bill_logs WHERE user_id = %s AND subscription_id = %s;", (uid, sub_id))
    for (pe_id,) in cur.fetchall():
        if pe_id is not None:
            cur.execute("DELETE FROM pocket_entries WHERE id = %s AND user_id = %s;", (pe_id, uid))

    cur.execute("DELETE FROM subscriptions WHERE id = %s AND user_id = %s RETURNING id;", (sub_id, uid))
    deleted = cur.fetchone()
    if not deleted:
        raise HTTPException(status_code=404, detail="指定したサブスクが見つかりませんでした")
    return {"status": "success", "deleted_id": deleted[0]}


# ==========================================
# ルーティング: おこづかい帳・明細管理
# ==========================================
@app.get("/pocket-entries")
def get_pocket_entries(
    year: int = Query(..., ge=2000, le=2100),
    month: int = Query(..., ge=1, le=12),
    current_user: dict = Depends(get_current_user),
    cur=Depends(db_cursor),
):
    uid = current_user["user_id"]
    start_dt = date(year, month, 1)
    end_dt = date(year, month, calendar.monthrange(year, month)[1])

    cur.execute(
        """
        SELECT id, entry_type, amount, entry_date, title, category, payment_method, memo
        FROM pocket_entries
        WHERE user_id = %s AND entry_date BETWEEN %s AND %s
        ORDER BY entry_date DESC, id DESC;
        """,
        (uid, start_dt, end_dt),
    )
    rows = cur.fetchall()

    items = []
    income_total, expense_total, auto_sub_expense_total = 0, 0, 0

    for r in rows:
        etype, amt, memo_val = r[1], r[2], r[7] or ""
        is_auto_sub = (etype == "expense") and memo_val.startswith(AUTO_SUB_MEMO_PREFIX)
        if etype == "income":
            income_total += amt
        else:
            expense_total += amt
            if is_auto_sub:
                auto_sub_expense_total += amt

        item = format_pocket_entry(r)
        item["is_auto_sub"] = is_auto_sub
        items.append(item)

    return {
        "year": year,
        "month": month,
        "income_total": income_total,
        "expense_total": expense_total,
        "auto_sub_expense_total": auto_sub_expense_total,
        "balance": income_total - expense_total,
        "count": len(items),
        "items": items,
    }


@app.post("/pocket-entries")
def create_pocket_entry(entry: PocketEntryCreate, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    if entry.entry_type not in ("income", "expense"):
        raise HTTPException(status_code=400, detail="entry_type は income または expense を指定してください")
    if not entry.title.strip():
        raise HTTPException(status_code=400, detail="項目名を入力してください")

    uid = current_user["user_id"]
    clean_method = entry.payment_method.strip() or "現金"
    get_or_create_wallet_by_name(cur, uid, clean_method)
    cur.execute(
        """
        INSERT INTO pocket_entries (user_id, entry_type, amount, entry_date, title, category, payment_method, memo)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id, entry_type, amount, entry_date, title, category, payment_method, memo;
        """,
        (uid, entry.entry_type, int(entry.amount), entry.entry_date, entry.title.strip(), entry.category.strip() or "その他", clean_method, entry.memo.strip()),
    )
    return {"status": "success", "entry": format_pocket_entry(cur.fetchone())}


@app.put("/pocket-entries/{entry_id}")
def update_pocket_entry(entry_id: int, payload: PocketEntryUpdate, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    if payload.entry_type not in ("income", "expense"):
        raise HTTPException(status_code=400, detail="entry_type は income または expense を指定してください")

    uid = current_user["user_id"]
    cur.execute("SELECT payment_method FROM pocket_entries WHERE id = %s AND user_id = %s;", (entry_id, uid))
    old_row = cur.fetchone()
    if not old_row:
        raise HTTPException(status_code=404, detail="指定した明細が見つかりませんでした")

    new_method = (payload.payment_method or "").strip() or (old_row[0] or "現金")
    get_or_create_wallet_by_name(cur, uid, new_method)

    cur.execute(
        """
        UPDATE pocket_entries
        SET entry_type = %s, amount = %s, entry_date = %s, title = %s, category = %s, payment_method = %s, memo = %s
        WHERE id = %s AND user_id = %s
        RETURNING id, entry_type, amount, entry_date, title, category, payment_method, memo;
        """,
        (payload.entry_type, int(payload.amount), payload.entry_date, payload.title.strip(), (payload.category or "").strip() or "その他", new_method, (payload.memo or "").strip(), entry_id, uid),
    )
    return {"status": "success", "entry": format_pocket_entry(cur.fetchone())}


@app.post("/pocket-entries/{entry_id}/split")
def split_pocket_entry(entry_id: int, payload: PocketEntrySplit, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    split_amt = int(payload.split_amount)
    if split_amt <= 0:
        raise HTTPException(status_code=400, detail="切り出す金額は1円以上で指定してください")

    cur.execute(
        "SELECT id, entry_type, amount, entry_date, title, category, payment_method, memo FROM pocket_entries WHERE id = %s AND user_id = %s;",
        (entry_id, uid),
    )
    orig = cur.fetchone()
    if not orig:
        raise HTTPException(status_code=404, detail="指定した明細が見つかりませんでした")

    orig_amt = int(orig[2] or 0)
    if split_amt > orig_amt:
        raise HTTPException(status_code=400, detail=f"切り出す金額（{split_amt}円）が元の金額（{orig_amt}円）を超えています")

    remaining_amt = orig_amt - split_amt
    orig_type, orig_date, orig_title, orig_method = orig[1], orig[3], orig[4], orig[6] or "現金"
    new_date = payload.entry_date or orig_date
    new_method = (payload.payment_method or "").strip() or orig_method
    new_title = payload.title.strip()
    new_category = (payload.category or "").strip() or "その他"
    new_memo = (payload.memo or "").strip()

    remaining_entry = None
    if remaining_amt > 0:
        cur.execute(
            """
            UPDATE pocket_entries
            SET amount = %s WHERE id = %s AND user_id = %s
            RETURNING id, entry_type, amount, entry_date, title, category, payment_method, memo;
            """,
            (remaining_amt, entry_id, uid),
        )
        remaining_entry = format_pocket_entry(cur.fetchone())
    else:
        cur.execute("DELETE FROM pocket_entries WHERE id = %s AND user_id = %s;", (entry_id, uid))

    cur.execute(
        """
        INSERT INTO pocket_entries (user_id, entry_type, amount, entry_date, title, category, payment_method, memo)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id, entry_type, amount, entry_date, title, category, payment_method, memo;
        """,
        (uid, orig_type, split_amt, new_date, new_title[:120], new_category, new_method, new_memo or f"「{orig_title}」から切り出し"),
    )
    split_entry = format_pocket_entry(cur.fetchone())

    return {"status": "success", "remaining_entry": remaining_entry, "split_entry": split_entry}


@app.delete("/pocket-entries/{entry_id}")
def delete_pocket_entry(entry_id: int, current_user: dict = Depends(get_current_user), cur=Depends(db_cursor)):
    uid = current_user["user_id"]
    cur.execute("DELETE FROM pocket_entries WHERE id = %s AND user_id = %s RETURNING id;", (entry_id, uid))
    deleted = cur.fetchone()
    if not deleted:
        raise HTTPException(status_code=404, detail="指定した明細が見つかりませんでした")
    return {"status": "success", "deleted_id": deleted[0]}
