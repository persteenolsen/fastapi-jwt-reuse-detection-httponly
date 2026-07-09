from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship

from db.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    username = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    # 25-12-2025 - Added Users Name
    name = Column(
        String,
        index=True,
        nullable=False,
    )

    email = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    hashed_password = Column(
        String,
        nullable=False,
    )

    # 06-07-2026 - Added relationship for Refresh Tokens
    refresh_tokens = relationship(
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
    )