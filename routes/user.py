from fastapi import APIRouter, Depends, Body, HTTPException, Response, Request
from sqlalchemy.orm import Session
from datetime import datetime

from db.database import get_db

from services.users import (
    get_current_username,
    get_current_user,
    get_all_users,
    do_register_user,
    get_access_token_for_login,
    get_tokens_for_login_spa,
    get_tokens_and_type,
    logout,
    logout_all,
    cleanup_refresh_tokens,
)

from models.user import User
from models.refresh_token import RefreshToken

from schemas.user import User as UserSchema
from schemas.token import Token as TokenSchema
from schemas.token import BothTokensSPA as BothTokensSchemaSPA


router_auth = APIRouter()


# =====================================================
# Cookie settings
# =====================================================

ACCESS_COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str
):

    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=access_token,
        httponly=True,

        # For testing locally
        secure=False,
        samesite="lax",

        # For production
        # secure=True
        # samesite="none"

        max_age=15 * 60
    )

    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,

        # For testing locally
        secure=False,
        samesite="lax",
        
        # For production
        # secure=True
        # samesite="none"

        max_age=7 * 24 * 60 * 60
    )


def clear_auth_cookies(response: Response):

    response.delete_cookie(
        ACCESS_COOKIE_NAME
    )

    response.delete_cookie(
        REFRESH_COOKIE_NAME
    )


# =====================================================
# Admin
# =====================================================

@router_auth.post(
    "/admin/purge-refresh-tokens",
    tags=["admin"]
)
def purge_refresh_tokens(
    db: Session = Depends(get_db),
    username: str = Depends(get_current_username)
):

    if username != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )

    deleted_count = db.query(
        RefreshToken
    ).delete()

    db.commit()

    return {
        "message": "All refresh tokens purged",
        "deleted_tokens": deleted_count,
        "executed_by": username,
        "timestamp": datetime.utcnow()
    }


@router_auth.post(
    "/cleanup-tokens",
    tags=["admin"]
)
async def cleanup_tokens(
    db: Session = Depends(get_db)
):

    return await cleanup_refresh_tokens(db)


# =====================================================
# Logout
# =====================================================

@router_auth.post(
    "/logout-all",
    tags=["user"]
)
async def logout_everywhere(
    username: str = Depends(get_current_username),
    db: Session = Depends(get_db)
):

    return await logout_all(
        username,
        db
    )


@router_auth.post(
    "/logout",
    tags=["user"]
)
async def logout_user(
    response: Response,
    result = Depends(logout)
):

    clear_auth_cookies(response)

    return result


# =====================================================
# Registration
# =====================================================

def register_user(
    new_user = Depends(do_register_user)
):
    return new_user


# =====================================================
# Swagger OAuth2 login
#
# DO NOT CHANGE THIS
# Swagger uses this endpoint
# =====================================================

@router_auth.post(
    "/token",
    response_model=TokenSchema,
    tags=["user"]
)
def login_for_access_token(
    token_and_type = Depends(
        get_access_token_for_login
    )
):

    return token_and_type


# =====================================================
# Vue Cookie Login
#
# New endpoint for SPA
# =====================================================

@router_auth.post(
    "/login-cookie",
    tags=["user"]
)
def login_cookie(
    response: Response,
    tokens = Depends(get_tokens_for_login_spa)
):

    set_auth_cookies(
        response,
        tokens["jwtToken"],
        tokens["refreshToken"]
    )

    return {
        "username": tokens["username"],
        "token_type": tokens["token_type"]
    }


# =====================================================
# Optional old SPA login
# Keeps compatibility
# =====================================================

@router_auth.post(
    "/tokens-spa",
    response_model=BothTokensSchemaSPA,
    tags=["user"]
)
def login_for_tokens_spa(
    tokens_type_username = Depends(
        get_tokens_for_login_spa
    )
):

    return tokens_type_username


# =====================================================
# Refresh token using HttpOnly cookie
# =====================================================

@router_auth.post(
    "/refresh-token-spa",
    tags=["user"]
)
async def refresh_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):

    refresh_token = request.cookies.get(
        REFRESH_COOKIE_NAME
    )

    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token missing"
        )


    result = await get_tokens_and_type(
        refresh_token,
        db
    )


    set_auth_cookies(
        response,
        result["jwtToken"],
        result["refreshToken"]
    )


    return {
        "username": result["username"],
        "token_type": result["token_type"]
    }


# =====================================================
# Protected routes
# =====================================================

@router_auth.get(
    "/users/me",
    response_model=UserSchema,
    tags=["user"]
)
def read_users_me(
    current_user: User = Depends(get_current_user)
):

    return current_user



@router_auth.get(
    "/protected-route",
    tags=["user"]
)
def secure_endpoint(
    username: str = Depends(get_current_username)
):

    return {
        "message":
        f"Hello {username}, you are authorized for this protected route!"
    }



@router_auth.get(
    "/get-all-users",
    response_model=list[UserSchema],
    tags=["user"]
)
def secure_endpoint(
    users = Depends(get_all_users)
):

    return users