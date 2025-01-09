from fastapi import FastAPI, Depends, HTTPException, status, Security, Response
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
import requests
import os
from dotenv import load_dotenv

my_model_path = "./model/unsloth.Q4_K_M.gguf"
CONTEXT_SIZE = 30000

tofood_model = Llama(model_path=my_model_path,n_ctx=CONTEXT_SIZE)

load_dotenv()

# ? config JWT
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 # 2 hari (belom permanen)


FURINA_API_KEY = os.getenv("FURINA_API_KEY")
if not FURINA_API_KEY:
    raise ValueError("FURINA_API_KEY is not set in .env or environment variables.")

#? OAuth2 Scheme dari FastAPI security 
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

class PromptRequest(BaseModel):
    instruction: str
    input: str

class APIKeys(SQLModel, table =True):
    id: str= Field(primary_key=True)
    name: str = Field(index=True)
    api_key: str 
    
class APIKeyGenerateRequest(BaseModel):
    name: str

class DecryptRequest(BaseModel):
    key_id: str
    cipher_text: str
    iv: str

class Customers(SQLModel, table =True):
    id: str = Field(primary_key=True)
    name: str = Field(index=True)
    hashed_password: str
    
class CustomerCreate(BaseModel):
    name: str
    password: str

class RevokedToken(SQLModel, table=True):
    id: str = Field(primary_key=True)
    token: str = Field(index=True)

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

def create_customer_in_db(name: str, hashed_password: str) -> Customers:
    new_id = str(uuid4())
    new_customer = Customers(
        id=new_id,
        name=name,
        hashed_password=hashed_password
    )
    with Session(engine) as session:
        session.add(new_customer)
        session.commit()
        session.refresh(new_customer)
        return new_customer

def get_customer_by_name(name: str) -> Customers | None:
    with Session(engine) as session:
        customer = session.exec(
            select(Customers).where(Customers.name == name)
        ).first()
        return customer

def authenticate_customer(username: str, password: str) -> Customers | None:
    customer = get_customer_by_name(username)
    if not customer:
        return None
    if not verify_password(password, customer.hashed_password):
        return None
    return customer

async def get_current_customer(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    with Session(engine) as session:
        blacklisted = session.exec(
            select(RevokedToken).where(RevokedToken.token == token)
        ).first()
        if blacklisted:
            raise HTTPException(
                status_code=401,
                detail="Token has been revoked"
            )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    customer = get_customer_by_name(username)
    if not customer:
        raise credentials_exception
    return customer

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

api_key_header = APIKeyHeader(name ="X-API-KEY")

def get_service_with_api_key(api_key: str = Security(api_key_header)):
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


#? "start" of the program
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
    
@app.get("/api/customers")
def read_customers():
    with Session(engine) as session:
        customers = session.exec(select(Customers)).all()
        return customers

@app.post("/api/customers/register")
def register_customer(data: CustomerCreate):
    existing = get_customer_by_name(data.name)
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Customer with name={data.name} already exists."
        )
    hashed = get_password_hash(data.password)
    new_customer = create_customer_in_db(data.name, hashed)
    return {
        "id": new_customer.id,
        "name": new_customer.name,
        "message": "Customer created successfully."
    }

@app.post("/api/customers/token")
def login_customer(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Menerima form field 'username' dan 'password'.
    Jika valid, buat JWT token dan kembalikan.
    """
    user = authenticate_customer(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    # Buat token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.name},  # 'sub' diisi user.name
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/customers/me")
def get_my_profile(current_customer: Customers = Depends(get_current_customer)):
    """
    Hanya bisa diakses jika JWT token valid di 'Authorization: Bearer <token>'.
    """
    return {
        "id": current_customer.id,
        "name": current_customer.name
    }
    
@app.post("/api/customers/logout")
def logout_customer(
    current_customer: Customers = Depends(get_current_customer),
    token: str = Depends(oauth2_scheme)
):
    """
    Memasukkan token saat ini ke blacklist.
    Sehingga user tidak bisa menggunakan token setelah logout.
    """
    with Session(engine) as session:
        # Simpan token di DB
        revoked = RevokedToken(
            id=str(uuid4()),
            token=token
        )
        session.add(revoked)
        session.commit()
    return {"message": f"User {current_customer.name} logged out and token revoked."}
    
# ? see api keys list
@app.get("/api/api-keys")
def read_api_keys():
    with Session(engine) as session:
        apikeys = session.exec(select(APIKeys)).all()
        return apikeys

# ? generate api key stuffs
@app.post("/api/api-keys/generate")
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
    

# ? main stuffs
@app.post("/api/services/prompt")
async def get_prompt(request_body: PromptRequest, _ :dict = Depends(get_service_with_api_key) ):
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
        "recipe_result": final_output,
        
    }
    
@app.post("/api/services/prompt-secret")
async def get_prompt_secret(
    request_body: PromptRequest,
    _ :dict = Depends(get_service_with_api_key)
):
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
    encryption_service_url = "https://furina-encryption-service.codebloop.my.id/api/encrypt"

    headers = {
        "accept": "application/json",
        "furina-encryption-service": FURINA_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "text": final_output,
        "sensitivity": "medium"
    }

    try:
        encrypt_response = requests.post(
            encryption_service_url,
            headers=headers,
            json=payload,
            timeout=10
        )
        encrypt_response.raise_for_status()  # if status != 200
    except requests.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error calling encryption service: {str(e)}"
        )


    encrypted_data = encrypt_response.json()
    return {
        "key_id": encrypted_data["key_id"],
        "cipher_recipe_result": encrypted_data["cipher_text"],
        "iv": encrypted_data["iv"]
    }
    
@app.post("/api/services/prompt-decrypt")
async def get_prompt_decrypt(
    body: DecryptRequest,
    _: dict = Depends(get_service_with_api_key)
):
    decrypt_service_url = "https://furina-encryption-service.codebloop.my.id/api/decrypt"

    headers = {
        "accept": "application/json",
        "furina-encryption-service": FURINA_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "key_id": body.key_id,
        "cipher_text": body.cipher_text,
        "iv": body.iv
    }
    try:
        response = requests.post(
            decrypt_service_url,
            headers=headers,
            json=payload,
            timeout=10
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error calling decryption service: {str(e)}"
        )
    decrypted_data = response.json()
    return {
        "decrypted_cipher_recipe_result": decrypted_data["text"]
    }


@app.post("/api/customers/prompt")
async def get_prompt(request_body: PromptRequest, _ :dict = Depends(get_current_customer)):
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
        "recipe_result": final_output,
    }

@app.post("/api/customers/prompt-secret")
async def get_prompt_secret(
    request_body: PromptRequest,
    _: dict = Depends(get_current_customer)
):
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
    encryption_service_url = "https://furina-encryption-service.codebloop.my.id/api/encrypt"

    headers = {
        "accept": "application/json",
        "furina-encryption-service": FURINA_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "text": final_output,
        "sensitivity": "medium"
    }

    try:
        encrypt_response = requests.post(
            encryption_service_url,
            headers=headers,
            json=payload,
            timeout=10
        )
        encrypt_response.raise_for_status()  # if status != 200
    except requests.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error calling encryption service: {str(e)}"
        )


    encrypted_data = encrypt_response.json()
    return {
        "key_id": encrypted_data["key_id"],
        "cipher_recipe_result": encrypted_data["cipher_text"],
        "iv": encrypted_data["iv"]
    }
    

@app.post("/api/customers/prompt-decrypt")
async def get_prompt_decrypt(
    body: DecryptRequest,
    _: dict = Depends(get_current_customer)
):
    """
    1) Menerima key_id, cipher_text, dan iv
    2) Kirim ke teman service (furina) untuk didekripsi
    3) Kembalikan hasil dekripsi ke end user
    """
    decrypt_service_url = "https://furina-encryption-service.codebloop.my.id/api/decrypt"

    headers = {
        "accept": "application/json",
        "furina-encryption-service": FURINA_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "key_id": body.key_id,
        "cipher_text": body.cipher_text,
        "iv": body.iv
    }

    try:
        response = requests.post(
            decrypt_service_url,
            headers=headers,
            json=payload,
            timeout=10
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error calling decryption service: {str(e)}"
        )
    decrypted_data = response.json()

    return {
      "decrypted_cipher_recipe_result": decrypted_data["text"]
    }
