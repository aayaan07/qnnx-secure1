"""add monitoring and heartbeats tables

Revision ID: a3f1c9e2b847
Revises: 559ff94c3da4
Create Date: 2026-06-21 08:22:00.000000

Adds six new tables:
  heartbeats       — append-only heartbeat log per VPN session (FK → sessions)
  system_metrics   — CPU/RAM/disk readings from the Monitoring Agent (FK → clients)
  user_activities  — login/logout/failed_login events from Windows Security log (FK → clients)
  network_activities — network connection and IP-change events (FK → clients)
  process_events   — process launch/terminate events from WMI watcher (FK → clients)
  device_events    — USB insertion/removal events from WMI watcher (FK → clients)

All tables have:
  - Cascade-delete FK to their parent (sessions or clients)
  - Composite index on (client_id/session_id + timestamp) for time-range queries
  - Individual index on client_id/session_id for lookup queries
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a3f1c9e2b847'
down_revision: Union[str, Sequence[str], None] = '559ff94c3da4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the 6 new monitoring/heartbeat tables."""

    # ------------------------------------------------------------------
    # heartbeats — append-only heartbeat log (FK → sessions)
    # ------------------------------------------------------------------
    op.create_table(
        'heartbeats',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('session_id', sa.UUID(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('sequence_number', sa.Integer(), server_default='0', nullable=False),
        sa.Column('packets_sent', sa.BigInteger(), server_default='0', nullable=False),
        sa.Column('packets_received', sa.BigInteger(), server_default='0', nullable=False),
        sa.ForeignKeyConstraint(['session_id'], ['sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_heartbeats_session_id_timestamp',
        'heartbeats',
        ['session_id', 'timestamp'],
        unique=False,
    )
    op.create_index('ix_heartbeats_session_id', 'heartbeats', ['session_id'], unique=False)

    # ------------------------------------------------------------------
    # system_metrics — CPU/RAM/disk snapshots (FK → clients)
    # ------------------------------------------------------------------
    op.create_table(
        'system_metrics',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('cpu_percent', sa.Float(), nullable=False),
        sa.Column('ram_percent', sa.Float(), nullable=False),
        sa.Column('disk_percent', sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(['client_id'], ['clients.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_system_metrics_client_id_timestamp',
        'system_metrics',
        ['client_id', 'timestamp'],
        unique=False,
    )
    op.create_index('ix_system_metrics_client_id', 'system_metrics', ['client_id'], unique=False)

    # ------------------------------------------------------------------
    # user_activities — login/logout events (FK → clients)
    # ------------------------------------------------------------------
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
        'ix_user_activities_client_id_timestamp',
        'user_activities',
        ['client_id', 'timestamp'],
        unique=False,
    )
    op.create_index('ix_user_activities_client_id', 'user_activities', ['client_id'], unique=False)
    op.create_index('ix_user_activities_event_type', 'user_activities', ['event_type'], unique=False)

    # ------------------------------------------------------------------
    # network_activities — TCP connections and IP-change events (FK → clients)
    # ------------------------------------------------------------------
    op.create_table(
        'network_activities',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('event_type', sa.Text(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['clients.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_network_activities_client_id_timestamp',
        'network_activities',
        ['client_id', 'timestamp'],
        unique=False,
    )
    op.create_index(
        'ix_network_activities_client_id', 'network_activities', ['client_id'], unique=False
    )
    op.create_index(
        'ix_network_activities_event_type', 'network_activities', ['event_type'], unique=False
    )

    # ------------------------------------------------------------------
    # process_events — process launch/terminate events (FK → clients)
    # ------------------------------------------------------------------
    op.create_table(
        'process_events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('process_name', sa.Text(), nullable=False),
        sa.Column('pid', sa.Integer(), nullable=True),
        sa.Column('action', sa.Text(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['client_id'], ['clients.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_process_events_client_id_timestamp',
        'process_events',
        ['client_id', 'timestamp'],
        unique=False,
    )
    op.create_index('ix_process_events_client_id', 'process_events', ['client_id'], unique=False)
    op.create_index(
        'ix_process_events_process_name', 'process_events', ['process_name'], unique=False
    )

    # ------------------------------------------------------------------
    # device_events — USB insertion/removal events (FK → clients)
    # ------------------------------------------------------------------
    op.create_table(
        'device_events',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('client_id', sa.UUID(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
        sa.Column('action', sa.Text(), nullable=False),
        sa.Column('device_info', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['clients.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_device_events_client_id_timestamp',
        'device_events',
        ['client_id', 'timestamp'],
        unique=False,
    )
    op.create_index('ix_device_events_client_id', 'device_events', ['client_id'], unique=False)
    op.create_index('ix_device_events_action', 'device_events', ['action'], unique=False)


def downgrade() -> None:
    """Drop the 6 new monitoring/heartbeat tables in reverse creation order."""

    # device_events
    op.drop_index('ix_device_events_action', table_name='device_events')
    op.drop_index('ix_device_events_client_id', table_name='device_events')
    op.drop_index('ix_device_events_client_id_timestamp', table_name='device_events')
    op.drop_table('device_events')

    # process_events
    op.drop_index('ix_process_events_process_name', table_name='process_events')
    op.drop_index('ix_process_events_client_id', table_name='process_events')
    op.drop_index('ix_process_events_client_id_timestamp', table_name='process_events')
    op.drop_table('process_events')

    # network_activities
    op.drop_index('ix_network_activities_event_type', table_name='network_activities')
    op.drop_index('ix_network_activities_client_id', table_name='network_activities')
    op.drop_index('ix_network_activities_client_id_timestamp', table_name='network_activities')
    op.drop_table('network_activities')

    # user_activities
    op.drop_index('ix_user_activities_event_type', table_name='user_activities')
    op.drop_index('ix_user_activities_client_id', table_name='user_activities')
    op.drop_index('ix_user_activities_client_id_timestamp', table_name='user_activities')
    op.drop_table('user_activities')

    # system_metrics
    op.drop_index('ix_system_metrics_client_id', table_name='system_metrics')
    op.drop_index('ix_system_metrics_client_id_timestamp', table_name='system_metrics')
    op.drop_table('system_metrics')

    # heartbeats
    op.drop_index('ix_heartbeats_session_id', table_name='heartbeats')
    op.drop_index('ix_heartbeats_session_id_timestamp', table_name='heartbeats')
    op.drop_table('heartbeats')
