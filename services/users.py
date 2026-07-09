from fastapi import (
    Depends,
    HTTPException,
    status,
    Body,
    Request
)

from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm
)

from sqlalchemy.orm import Session

from models.refresh_token import RefreshToken
from models.user import User

from security.auth import (
    decode_token_payload,
    verify_password,
    verify_token,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    hash_refresh_token
)

from db.database import get_db

from schemas.user import UserCreate as UserCreateSchema

from pydantic import BaseModel

import os

from datetime import (
    datetime,
    timedelta,
    timezone
)


REFRESH_TOKEN_EXPIRE_MINUTES = int(
    os.getenv(
        "REFRESH_TOKEN_EXPIRE_MINUTES"
    )
)


# =====================================================
# OAuth2
#
# auto_error=False allows cookie authentication
# while keeping Swagger support
# =====================================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    auto_error=False
)

from fastapi import Request

def get_access_token(
    request: Request,
    bearer_token: str | None = Depends(oauth2_scheme)
):
    """
    Authentication helper.

    Priority:
    1. HttpOnly access_token cookie (Vue SPA)
    2. Authorization Bearer header (Swagger)
    """

    cookie_token = request.cookies.get("access_token")

    if cookie_token:
        return cookie_token

    if bearer_token:
        return bearer_token

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )

ACCESS_COOKIE_NAME = "access_token"


# =====================================================
# Logout
# =====================================================
async def logout(
    request: Request,
    db: Session = Depends(get_db)
):

    refresh_token = request.cookies.get(
        "refresh_token"
    )

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing"
        )


    token_hash = hash_refresh_token(
        refresh_token
    )


    db_token = db.query(
        RefreshToken
    ).filter(
        RefreshToken.token_hash == token_hash
    ).first()


    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found"
        )


    if db_token.revoked_at is not None:
        return {
            "message": "Already logged out"
        }


    db_token.revoked_at = datetime.utcnow()

    db.commit()


    return {
        "message": "Successfully logged out"
    }


async def logout_all(
    username: str,
    db: Session
):

    user = db.query(
        User
    ).filter(
        User.username == username
    ).first()


    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )


    tokens = db.query(
        RefreshToken
    ).filter(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked_at == None
    ).all()


    for token in tokens:
        token.revoked_at = datetime.utcnow()


    db.commit()


    return {
        "message": "Logged out from all sessions"
    }



# =====================================================
# Refresh token reuse detection
# =====================================================

def revoke_refresh_token_family(
    db: Session,
    token_jti: str
):

    current_token = db.query(
        RefreshToken
    ).filter(
        RefreshToken.jti == token_jti
    ).first()


    if current_token is None:
        return


    now = datetime.utcnow()


    active_tokens = db.query(
        RefreshToken
    ).filter(
        RefreshToken.user_id == current_token.user_id,
        RefreshToken.revoked_at.is_(None)
    ).all()


    for token in active_tokens:
        token.revoked_at = now


    db.commit()



# =====================================================
# Cleanup
# =====================================================

async def cleanup_refresh_tokens(
    db: Session = Depends(get_db)
):

    cutoff = datetime.utcnow() - timedelta(days=7)


    revoked = db.query(
        RefreshToken
    ).filter(
        RefreshToken.revoked_at != None,
        RefreshToken.revoked_at < cutoff
    ).all()


    expired = db.query(
        RefreshToken
    ).filter(
        RefreshToken.expires_at < cutoff
    ).all()


    tokens = set(
        revoked + expired
    )


    for token in tokens:
        db.delete(token)


    db.commit()


    return {
        "message": "Cleanup completed",
        "deleted_tokens": len(tokens)
    }



# =====================================================
# Registration
# =====================================================

def do_register_user(
    user: UserCreateSchema,
    db: Session = Depends(get_db)
):

    existing = db.query(
        User
    ).filter(
        User.username == user.username
    ).first()


    if existing:
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )


    new_user = User(
        username=user.username,
        name=user.name,
        email=user.email,
        hashed_password=get_password_hash(
            user.password
        )
    )


    db.add(new_user)
    db.commit()
    db.refresh(new_user)


    return new_user



# =====================================================
# Swagger /token
#
# unchanged behaviour
# =====================================================

def get_access_token_for_login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):

    user = db.query(
        User
    ).filter(
        User.username == form_data.username
    ).first()


    if not user or not verify_password(
        form_data.password,
        user.hashed_password
    ):

        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )


    access_token = create_access_token(
        {
            "sub": user.username
        }
    )


    return {
        "access_token": access_token,
        "token_type": "bearer"
    }



# =====================================================
# SPA login token creation
# =====================================================

def get_tokens_for_login_spa(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):

    user = db.query(
        User
    ).filter(
        User.username == form_data.username
    ).first()


    if not user or not verify_password(
        form_data.password,
        user.hashed_password
    ):

        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password"
        )


    access_token = create_access_token(
        {
            "sub": user.username
        }
    )


    refresh_token = create_refresh_token(
        {
            "sub": user.username
        }
    )


    payload = decode_token_payload(
        refresh_token
    )


    db_token = RefreshToken(
        user_id=user.id,
        jti=payload["jti"],
        token_hash=hash_refresh_token(
            refresh_token
        ),
        expires_at=datetime.utcnow()
        + timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES
        ),
        revoked_at=None,
        replaced_by_jti=None,
        parent_jti=None
    )


    db.add(db_token)
    db.commit()


    return {
        "jwtToken": access_token,
        "refreshToken": refresh_token,
        "token_type": "bearer",
        "username": user.username
    }



# =====================================================
# Refresh rotation
# =====================================================

async def get_tokens_and_type(
    refreshToken: str,
    db: Session
):

    payload = decode_token_payload(
        refreshToken
    )


    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )


    username = payload.get(
        "sub"
    )


    token_hash = hash_refresh_token(
        refreshToken
    )


    db_token = db.query(
        RefreshToken
    ).filter(
        RefreshToken.token_hash == token_hash
    ).first()


    if not db_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found"
        )


    if db_token.revoked_at is not None:

        if db_token.replaced_by_jti:

            revoke_refresh_token_family(
                db,
                db_token.jti
            )

            raise HTTPException(
                status_code=401,
                detail="Refresh token reuse detected"
            )


        raise HTTPException(
            status_code=401,
            detail="Refresh token revoked"
        )



    if db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=401,
            detail="Refresh token expired"
        )


    new_access = create_access_token(
        {
            "sub": username
        }
    )


    new_refresh = create_refresh_token(
        {
            "sub": username
        }
    )


    new_payload = decode_token_payload(
        new_refresh
    )


    db_token.revoked_at = datetime.utcnow()
    db_token.replaced_by_jti = new_payload["jti"]


    new_db_token = RefreshToken(
        user_id=db_token.user_id,
        jti=new_payload["jti"],
        token_hash=hash_refresh_token(
            new_refresh
        ),
        expires_at=datetime.utcnow()
        + timedelta(
            minutes=REFRESH_TOKEN_EXPIRE_MINUTES
        ),
        revoked_at=None,
        replaced_by_jti=None,
        parent_jti=db_token.jti
    )


    db.add(new_db_token)
    db.commit()


    return {
        "jwtToken": new_access,
        "refreshToken": new_refresh,
        "token_type": "bearer",
        "username": username
    }



# =====================================================
# Authentication helper
# Supports:
# - Swagger Bearer token
# - Vue HttpOnly cookie
# =====================================================

def get_token_from_request(
    request: Request,
    token: str | None
):

    if token:
        return token


    return request.cookies.get(
        ACCESS_COOKIE_NAME
    )


def get_current_user(
    request: Request,
    token: str = Depends(get_access_token),
    db: Session = Depends(get_db)
):
    username = verify_token(
        token,
        expected_type="access"
    )

    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials! Try to Authorize ...",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(
        User.username == username
    ).first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user

def get_current_username(
    request: Request,
    token: str = Depends(get_access_token)
):
    username = verify_token(
        token,
        expected_type="access"
    )

    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="The JWT Token is not valid or has expired! Try to Authorize ...",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return username


def get_all_users(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):

    token = get_token_from_request(
        request,
        token
    )


    username = verify_token(
        token,
        expected_type="access"
    )


    if username is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid token"
        )


    return db.query(
        User
    ).all()