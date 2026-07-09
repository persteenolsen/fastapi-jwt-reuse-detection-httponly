from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import relationship

from db.database import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(
        Integer,
        primary_key=True,
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # JWT unique identifier (jti claim)
    jti = Column(
        String,
        nullable=False,
        unique=True,
        index=True,
    )

    # SHA-256 hash of the refresh token
    token_hash = Column(
        String,
        nullable=False,
        unique=True,
        index=True,
    )

    # JWT expiration time
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
    )

    # Database insertion timestamp
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # NULL = active token, timestamp = revoked token
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Set when this token is rotated
    replaced_by_jti = Column(
        String,
        nullable=True,
    )

    # Previous token in the refresh token family
    parent_jti = Column(
        String,
        nullable=True,
    )

    user = relationship(
        "User",
        back_populates="refresh_tokens",
    )

    __table_args__ = (
        Index(
            "ix_refresh_tokens_user_expires",
            "user_id",
            "expires_at",
        ),
        Index(
            "ix_refresh_tokens_user_revoked",
            "user_id",
            "revoked_at",
        ),
    )