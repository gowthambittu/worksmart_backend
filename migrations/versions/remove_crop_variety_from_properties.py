from alembic import op
import sqlalchemy as sa


revision = 'remove_crop_variety_001'
down_revision = 'add_ml_attrs_001'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('properties') as batch_op:
        batch_op.drop_column('crop_variety')


def downgrade():
    with op.batch_alter_table('properties') as batch_op:
        batch_op.add_column(sa.Column('crop_variety', sa.String(length=100), nullable=True))
