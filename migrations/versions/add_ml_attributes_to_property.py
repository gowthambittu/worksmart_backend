from alembic import op
import sqlalchemy as sa


revision = 'add_ml_attrs_001'
down_revision = '21869f9887d4'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('properties', sa.Column('crop_type', sa.String(100), nullable=True))
    op.add_column('properties', sa.Column('crop_variety', sa.String(100), nullable=True))
    op.add_column('properties', sa.Column('season', sa.Enum('kharif', 'rabi', 'summer'), nullable=True))
    op.add_column('properties', sa.Column('harvest_count', sa.Integer(), nullable=True, server_default='0'))
    op.add_column('properties', sa.Column('plant_spacing_ft', sa.Float(), nullable=True))
    op.add_column('properties', sa.Column('soil_type', sa.Enum('black_cotton', 'red_sandy', 'clay_loam', 'sandy_loam', 'alluvial'), nullable=True))
    op.add_column('properties', sa.Column('is_irrigated', sa.Boolean(), nullable=True, server_default='0'))
    op.add_column('properties', sa.Column('irrigation_type', sa.Enum('drip', 'flood', 'rain_fed', 'sprinkler'), nullable=True))
    op.add_column('properties', sa.Column('fertilizer_type', sa.Enum('chemical', 'organic', 'mixed'), nullable=True))
    op.add_column('properties', sa.Column('avg_yield_per_acre', sa.Float(), nullable=True))


def downgrade():
    op.drop_column('properties', 'crop_type')
    op.drop_column('properties', 'crop_variety')
    op.drop_column('properties', 'season')
    op.drop_column('properties', 'harvest_count')
    op.drop_column('properties', 'plant_spacing_ft')
    op.drop_column('properties', 'soil_type')
    op.drop_column('properties', 'is_irrigated')
    op.drop_column('properties', 'irrigation_type')
    op.drop_column('properties', 'fertilizer_type')
    op.drop_column('properties', 'avg_yield_per_acre')
