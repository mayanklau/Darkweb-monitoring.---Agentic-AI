"""enterprise baseline

Revision ID: 0001_enterprise_baseline
Revises:
Create Date: 2026-05-19
"""

revision = "0001_enterprise_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The application uses SQLAlchemy create_all for local bootstrap. This migration marks the
    # enterprise baseline for teams that prefer Alembic-managed production schema rollout.
    pass


def downgrade() -> None:
    pass
