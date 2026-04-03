from alembic import op
import sqlalchemy as sa


revision = 'work_record_audit_001'
down_revision = 'remove_crop_variety_001'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'work_record_audits',
        sa.Column('audit_id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('record_id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('before_payload', sa.Text(), nullable=True),
        sa.Column('after_payload', sa.Text(), nullable=True),
        sa.Column('acted_by_user_id', sa.Integer(), nullable=False),
        sa.Column('acted_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.ForeignKeyConstraint(['acted_by_user_id'], ['users.user_id']),
    )


def downgrade():
    op.drop_table('work_record_audits')
