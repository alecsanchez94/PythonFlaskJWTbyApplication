from flask_sqlalchemy import SQLAlchemy
from flask_user import UserMixin
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from marshmallow import Schema, fields
from sqlalchemy import *
from sqlalchemy.orm import relationship
from sqlalchemy_serializer import SerializerMixin
from flask_server import db

class Role(db.Model, SerializerMixin):
    __tablename__ = "roles"
    serialize_only = ('id', 'name')

    id = Column(Integer(), primary_key=True, nullable=True)
    name = Column(String(50), unique=True)

    def drop(self):

        db.session.delete(self)
        db.session.commit()

    def save(self):
        db.session.add(self)
        db.session.commit()




class UserRoles(db.Model):
    __tablename__ = "user_roles"
    id = Column(Integer(), primary_key=True)
    user_id = Column(Integer(), ForeignKey('users.id', ondelete='CASCADE'))
    role_id = Column(Integer(), ForeignKey('roles.id', ondelete='CASCADE'))



class User(db.Model, UserMixin, SerializerMixin):
    __tablename__ = "users"
    serialize_only = ('id', 'email', 'first_name', 'last_name', 'is_activated', 'deactivated')

    id = Column(Integer(), primary_key=True)
    email = Column(String(255), nullable=False, unique=True)
    password = Column(String(500), nullable=False)
    first_name = Column(String(255), nullable=False)
    last_name = Column(String(255), nullable=False)
    is_activated = Column(Boolean(), default=False)
    created_on = Column(DateTime(), default=datetime.now())
    activated_on = Column(DateTime(), nullable=True)
    deactivated = Column(Boolean(), default=False)
    roles = relationship('Role', secondary='user_roles')

    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def serialize(self):
        roles = []
        for role in self.roles:
            roles.append(role.name)

        response = self.to_dict()
        response['roles'] = ", ".join(roles)
        return response

