from fastapi import FastAPI,Depends,HTTPException,status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from sqlalchemy import Column,Integer,String,create_engine,ForeignKey
from sqlalchemy.orm import sessionmaker,Session,relationship,DeclarativeBase
from passlib.context import CryptContext
import jwt
from datetime import datetime,timedelta
from pydantic import BaseModel


DB_URL = "sqlite:///main.db"
class Base(DeclarativeBase): pass 

engine = create_engine(DB_URL)

class User(Base):
    __tablename__ ="users"
    id = Column(Integer,primary_key=True,index=True)
    username = Column(String,index=True)
    hashed_password=Column(String)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(bind=engine)

def get_db():
     session = SessionLocal()
     try: 
          yield session
     finally:
          session.close()

class DataUser(BaseModel):
     username:str 
     password:str

crypto_context = CryptContext(schemes=['bcrypt'])
scheme_token = OAuth2PasswordBearer(tokenUrl='login')
app =FastAPI()

SECRET_KEY="12345"
ALGORITHM="HS256"

def create_access_token(data: dict, expires_delta: timedelta):
     data_to_encode = data.copy()
     expire = datetime.now() + expires_delta
     data_to_encode['exp'] = expire
     return jwt.encode(data_to_encode,SECRET_KEY,algorithm=ALGORITHM)

@app.post("/register")
def register(user:DataUser, db: Session = Depends(get_db)):
          hashed_psw = crypto_context.hash(user.password)
          db_user = User(username=user.username,hashed_password=hashed_psw)
          db.add(db_user)
          db.commit()
          return {"msg": "User registred successfully"}

@app.post("/login")
def login(form_data:OAuth2PasswordRequestForm = Depends(), db:Session =  Depends(get_db)):
      user = db.query(User).filter(User.username == form_data.username).first()
      if not user or not crypto_context.verify(form_data.password,user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Incorrect username or password")
      access_token=create_access_token(data={"username": user.username,"psw":user.hashed_password},expires_delta=timedelta(minutes=15)) 
      return {
            "access_token": access_token,
            "token_type": "bearer"
      }

@app.get("/resourse")
def info(token:str  = Depends(scheme_token) ):
      print(token)
      data:dict = jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
      username = data.get("username")
      if username==None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Could not validate credentials")
      return data


      

      












