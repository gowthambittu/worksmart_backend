"""Added paid_out to WorkOrder

Revision ID: 2512a00fa4e1
Revises: b4c7177f079a
Create Date: 2024-06-17 11:00:55.758649

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2512a00fa4e1'
down_revision = 'b4c7177f079a'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('work_orders', schema=None) as batch_op:
        batch_op.add_column(sa.Column('paid_out', sa.Float(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('work_orders', schema=None) as batch_op:
        batch_op.drop_column('paid_out')

    # ### end Alembic commands ###
