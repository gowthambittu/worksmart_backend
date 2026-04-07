from alembic import op
import sqlalchemy as sa


revision = 'work_order_rates_001'
down_revision = 'work_record_audit_001'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('work_orders', sa.Column('cost_to_labour', sa.Float(), nullable=True))
    op.add_column('work_orders', sa.Column('cost_to_driver', sa.Float(), nullable=True))

    op.execute(
        """
        UPDATE work_orders wo
        SET cost_to_labour = p.cost_to_labour,
            cost_to_driver = p.cost_to_driver
        FROM properties p
        WHERE wo.property_id = p.property_id
        """
    )


def downgrade():
    op.drop_column('work_orders', 'cost_to_driver')
    op.drop_column('work_orders', 'cost_to_labour')
