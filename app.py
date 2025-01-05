from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
from typing import Optional
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from pydantic import BaseModel
import bcrypt
from llama_cpp import Llama
from sqlmodel import Field, Session, SQLModel, create_engine, select
from uuid import uuid4
import secrets

my_model_path = "./model/unsloth.Q4_K_M.gguf"
CONTEXT_SIZE = 30000

tofood_model = Llama(model_path=my_model_path,n_ctx=CONTEXT_SIZE)

app = FastAPI()

class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str

class PromptRequest(BaseModel):
    instruction: str
    input: str


class APIKeys(SQLModel, table =True):
    id: str= Field(primary_key=True)
    name: str = Field(index=True)
    api_key: str 

# TODO implement like api keys (database)
class Customers(SQLModel, table =True):
    id: str = Field(primary_key=True)
    name: str = Field(index=True)
    hashed_password: str


def get_password_hash(password):
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
    string_password = hashed_password.decode('utf8')
    return string_password


def verify_password(plain_password, hashed_password):
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_byte_enc, hashed_password)

# ? dummy database
dummy_users_db = {
    "diddy": {
        "username": "diddy",
        "hashed_password": get_password_hash("secret"),
    }
}

# ? config JWT
SECRET_KEY = "diddy-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#? OAuth2 Scheme dari FastAPI security 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_user(username: str):
    user = dummy_users_db.get(username)
    if user:
        return UserInDB(**user)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ? function for dependency/session
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

api_key_header = APIKeyHeader(name ="X-API-KEY")

def get_user_with_api_key(api_key: str = Security(api_key_header)):
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-KEY header"
        )
    with Session(engine) as session:
        result = session.exec(
            select(APIKeys).where(APIKeys.api_key == api_key)
        ).first()
        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key"
            )
        return result

sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

connect_args = {"check_same_thread": False}
engine = create_engine(sqlite_url, echo=True, connect_args=connect_args)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.get("/sample")
async def index():
    return {
        "info": "Try /hello/Sandro for parameterized route.",
    }
    
@app.get("/hello/{name}")
async def get_name(name: str):
    return {
        "name": name,
    }
    
@app.post("/api/customers")
def create_customer(customer: Customers):
    with Session(engine) as session:
        session.add(customer)
        session.commit()
        session.refresh(customer)
        return customer
    
@app.get("/api/customers")
def read_customers():
    with Session(engine) as session:
        customers = session.exec(select(Customers)).all()
        return customers
    

# ? endpoint for tokens
@app.post("/api/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ? protected route for testing
@app.get("/api/protected-route")
async def read_protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}!"}

# ? generate api key stuffs
class APIKeyGenerateRequest(BaseModel):
    name: str
    
@app.post("/api/generate-api-key")
def generate_api_key(req: APIKeyGenerateRequest):
    new_api_key_value = secrets.token_hex(16)
    new_id = str(uuid4())

    new_api = APIKeys(
        id=new_id,
        name=req.name,
        api_key=new_api_key_value
    )
    with Session(engine) as session:
        session.add(new_api)
        session.commit()
        session.refresh(new_api)
    return {
        "message": f"API key created for {req.name or 'Unnamed Service'}",
        "id": new_id,
        "api_key": new_api_key_value
    }
    
# ? see api keys list
@app.get("/api/api-keys")
def read_api_keys():
    with Session(engine) as session:
        apikeys = session.exec(select(APIKeys)).all()
        return apikeys

# ? main stuffs
@app.post("/api/prompt")
async def get_prompt(request_body: PromptRequest, _ :dict = Depends(get_user_with_api_key) ):

    prompt = f"""
instruction:{request_body.instruction}
input:{request_body.input}
"""

    generation_kwargs = {
        "max_tokens": 10000,
        "stop": ["</s>"],
        "echo": False,
        "top_k": 1
    }

    print("Processing....")
    res = tofood_model(prompt, **generation_kwargs)
    final_output: str = res["choices"][0]["text"]
    
    return {
        "Output": final_output,
    }