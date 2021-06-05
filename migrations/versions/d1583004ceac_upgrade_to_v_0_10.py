"""Upgrade to v 0.10

Revision ID: d1583004ceac
Revises: 98f64c144070
Create Date: 2021-06-05 13:42:31.400469

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd1583004ceac'
down_revision = '98f64c144070'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('lastscan', schema=None) as batch_op:
        batch_op.create_unique_constraint('_uq_lastscan', ['target_id'])

    with op.batch_alter_table('scanresultshistory', schema=None) as batch_op:
        batch_op.drop_constraint('_uq_scanresultshistory', type_='unique')
        batch_op.create_unique_constraint('_uq_scanresultshistory', ['target_id', 'scanresult_id', 'timestamp'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('scanresultshistory', schema=None) as batch_op:
        batch_op.drop_constraint('_uq_scanresultshistory', type_='unique')
        batch_op.create_unique_constraint('_uq_scanresultshistory', ['target_id', 'scanresult_id'])

    with op.batch_alter_table('lastscan', schema=None) as batch_op:
        batch_op.drop_constraint('_uq_lastscan', type_='unique')

    # ### end Alembic commands ###
