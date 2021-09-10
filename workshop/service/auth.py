import datetime

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.hash import bcrypt
from pydantic import ValidationError
from sqlalchemy.orm import Session

from ..database import get_session
from ..models.auth import Token, User, UserCreate
from ..settings import settings
from ..tables import User as UserModel


oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/sign-in')


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    return AuthService.validate_token(token)


class AuthService:
    @classmethod
    def verify_password(cls, password: str, hash: str) -> bool:
        return bcrypt.verify(password, hash)

    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)

    @classmethod
    def validate_token(cls, token: str) -> User:
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm]
            )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        user_data = payload.get('user')
        try:
            user = User.parse_obj(user_data)
        except ValidationError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        return user

    @classmethod
    def create_token(cls, user: UserModel) -> Token:
        user_data = User.from_orm(user)
        now = datetime.datetime.utcnow()
        payload = {
            'iat': now,
            'nbf': now,
            'exp': now + datetime.timedelta(seconds=settings.jwt_expiration),
            'sub': str(user_data.id),
            'user': user_data.dict()
        }
        token = jwt.encode(
            payload,
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm
        )
        return Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register_new_user(self, user_data: UserCreate) -> Token:
        user = UserModel(
            email=user_data.email,
            username=user_data.username,
            password_hash=self.hash_password(user_data.password)
        )
        self.session.add(user)
        self.session.commit()
        return self.create_token(user)

    def authenticate_user(self, username: str, password: str) -> Token:
        user = (
            self.session
            .query(UserModel)
            .filter(UserModel.username == username)
            .first()
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        if not self.verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        return self.create_token(user)
