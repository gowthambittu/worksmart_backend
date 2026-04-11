from alembic import op
import sqlalchemy as sa


revision = 'plant_spacing_dims_001'
down_revision = 'kgs_units_001'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('properties', sa.Column('plant_spacing_row_in', sa.Float(), nullable=True))
    op.add_column('properties', sa.Column('plant_spacing_col_in', sa.Float(), nullable=True))
    op.add_column('properties', sa.Column('plant_spacing_sqft', sa.Float(), nullable=True))

    # Best-effort backfill from legacy 1D feet spacing (assume square spacing).
    op.execute(
        """
        UPDATE properties
        SET plant_spacing_row_in = plant_spacing_ft * 12,
            plant_spacing_col_in = plant_spacing_ft * 12,
            plant_spacing_sqft = ((plant_spacing_ft * 12) * (plant_spacing_ft * 12)) / 144
        WHERE plant_spacing_ft IS NOT NULL
          AND plant_spacing_row_in IS NULL
          AND plant_spacing_col_in IS NULL
        """
    )


def downgrade():
    op.drop_column('properties', 'plant_spacing_sqft')
    op.drop_column('properties', 'plant_spacing_col_in')
    op.drop_column('properties', 'plant_spacing_row_in')
