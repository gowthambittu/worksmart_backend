from alembic import op
import sqlalchemy as sa


revision = 'kgs_units_001'
down_revision = 'work_order_rates_001'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('work_records', sa.Column('work_done_kgs', sa.Float(), nullable=True))
    op.add_column('outbound_records', sa.Column('weight_in_kgs', sa.Numeric(12, 2), nullable=True))

    op.execute(
        """
        UPDATE work_records
        SET work_done_kgs = work_done_tons * 1000
        WHERE work_done_tons IS NOT NULL AND work_done_kgs IS NULL
        """
    )

    op.execute(
        """
        UPDATE outbound_records
        SET weight_in_kgs = weight_in_tons * 1000
        WHERE weight_in_tons IS NOT NULL AND weight_in_kgs IS NULL
        """
    )


def downgrade():
    op.drop_column('outbound_records', 'weight_in_kgs')
    op.drop_column('work_records', 'work_done_kgs')
