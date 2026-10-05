from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(db.Model):

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False,
        index=True
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = db.Column(
        db.String(500),
        nullable=False
    )

    phone_encrypted = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    capabilities = db.relationship(
        "Capability",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )


class Capability(db.Model):

    __tablename__ = "capabilities"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    code_hash = db.Column(
        db.String(64),
        nullable=False,
        index=True
    )

    scope = db.Column(
        db.String(100),
        nullable=False
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False
    )

    used = db.Column(
        db.Boolean,
        default=False,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
