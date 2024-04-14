
from fastapi import FastAPI, Depends, HTTPException, status
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta

ALGORITHM = "HS256"
ACCESS_TOKEN_DURATION = 1

app = FastAPI()

oauth2 = OAuth2PasswordBearer(tokenUrl="login")

crypt = CryptContext(schemes=["bcrypt"])

class User(BaseModel):
    username: str
    full_name: str
    email: str
    disabled: bool

class UserDB(User):
    password:str

users_bd = {
    "yxavier":{
        "username": "yxavier",
        "full_name": "yxa machado",
        "email": "machadoyxa@gmail.com",
        "disabled": False,
        "password": "$2a$12$gAZumj9CPvNwT2GnTGLrfuBXaQlgXSGMU8CJM9xrdhvZD6VsiMolq"
    },
    "yxavier2":{
        "username": "yxavier2",
        "full_name": "yxa machado 2",
        "email": "machadoyxa2@gmail.com",
        "disabled": True,
        "password": "6$2a$12$QNkrBQ9KLgpngbTfdJhFReYTR7rWaVrzh7nVlPghylj8DlBCTWqD2"
    }
}

def search_user_db(username : str):
    if username in users_bd:
        return UserDB(**users_bd[username])
    
@app.post("/login")
async def login(form:OAuth2PasswordRequestForm = Depends()):
    user_db = users_bd.get(form.username)
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="El usuario no es correcto")
    
    user = search_user_db(form.username)

    if not crypt.verify(form.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="La contraseña no es correcta")
    
    access_token = {"sub": user.username,
                    "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_DURATION)}

    
    return {"access_token":access_token, "token_type":"bearer"}

