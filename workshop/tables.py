import sqlalchemy as s
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = s.Column(s.Integer, primary_key=True)
    email = s.Column(s.Text, unique=True)
    username = s.Column(s.Text, unique=True)
    password_hash = s.Column(s.Text)


class Operation(Base):
    __tablename__ = 'operations'

    id = s.Column(s.Integer, primary_key=True)
    user_id = s.Column(s.Integer, s.ForeignKey('users.id'))
    date = s.Column(s.Date)
    kind = s.Column(s.String)
    amount = s.Column(s.Numeric(10, 2))
    description = s.Column(s.String, nullable=True)
