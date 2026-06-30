"""drop user_activities table

Revision ID: 3b7e1f2a9c05
Revises: 0d936d7cfb67
Create Date: 2026-06-30 00:00:00.000000

user_activities is redundant — login/logout/failed_login events from the
Windows Security log are already captured as security alerts in qvpn_alerts.
Network activity (the sibling table) is populated directly by the agent;
user activity is not, and there is no plan to do so.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '3b7e1f2a9c05'
down_revision: Union[str, Sequence[str], None] = '0d936d7cfb67'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index('ix_user_activities_event_type', table_name='user_activities')
    op.drop_index('ix_user_activities_client_id', table_name='user_activities')
    op.drop_index('ix_user_activities_client_id_timestamp', table_name='user_activities')
    op.drop_table('user_activities')


def downgrade() -> None:
    op.create_table(
        'user_activities',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('event_type', sa.Text(), nullable=False),
        sa.Column('username', sa.Text(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['clients.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_user_activities_client_id_timestamp', 'user_activities',
        ['client_id', 'timestamp'], unique=False,
    )
    op.create_index('ix_user_activities_client_id', 'user_activities', ['client_id'], unique=False)
    op.create_index('ix_user_activities_event_type', 'user_activities', ['event_type'], unique=False)
