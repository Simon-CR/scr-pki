"""Add monitoring alert channels table and certificate monitoring fields

Revision ID: 20251118_01
Revises: 
Create Date: 2025-11-18 20:25:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "20251118_01"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


alert_channel_enum = postgresql.ENUM(
    "discord",
    "email",
    "telegram",
    "pushbullet",
    "other",
    name="alertchanneltype",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    alert_channel_enum.create(bind, checkfirst=True)

    op.add_column(
        "certificates",
        sa.Column(
            "monitoring_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "certificates",
        sa.Column("monitoring_target_url", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "certificates",
        sa.Column("monitoring_target_port", sa.Integer(), nullable=True),
    )
    op.add_column(
        "certificates",
        sa.Column("monitoring_channels", sa.JSON(), nullable=True),
    )
    op.add_column(
        "certificates",
        sa.Column("monitoring_notes", sa.Text(), nullable=True),
    )

    op.create_table(
        "monitoring_alert_channels",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("service_id", sa.Integer(), sa.ForeignKey("monitoring_services.id"), nullable=True),
        sa.Column("channel_type", alert_channel_enum, nullable=False),
        sa.Column("target", sa.String(length=512), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.execute("UPDATE certificates SET monitoring_enabled = FALSE WHERE monitoring_enabled IS NULL")
    op.alter_column("certificates", "monitoring_enabled", server_default=None)


def downgrade() -> None:
    op.drop_table("monitoring_alert_channels")
    op.drop_column("certificates", "monitoring_notes")
    op.drop_column("certificates", "monitoring_channels")
    op.drop_column("certificates", "monitoring_target_port")
    op.drop_column("certificates", "monitoring_target_url")
    op.drop_column("certificates", "monitoring_enabled")
    alert_channel_enum.drop(op.get_bind(), checkfirst=True)
