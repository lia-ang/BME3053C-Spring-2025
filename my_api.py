from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime
import jwt
from passlib.context import CryptContext

# Initialize FastAPI app
app = FastAPI(title="Patient Management System API")

# Security configurations
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Data Models
class PatientBase(BaseModel):
    name: str
    email: EmailStr
    date_of_birth: datetime
    medical_history: Optional[str] = None

class PatientCreate(PatientBase):
    password: str

class Patient(PatientBase):
    id: int
    created_at: datetime
    
    class Config:
        orm_mode = True

# Mock database
patients_db = {}
patient_id_counter = 1

# Authentication helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(email: str, password: str):
    if email not in patients_db:
        return False
    patient = patients_db[email]
    if not verify_password(password, patient['password']):
        return False
    return patient

# Dependency for getting current user
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception
    patient = patients_db.get(email)
    if patient is None:
        raise credentials_exception
    return patient

# API Endpoints
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token_data = {"sub": user['email']}
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@app.post("/patients/", response_model=Patient, status_code=status.HTTP_201_CREATED)
async def create_patient(patient: PatientCreate):
    global patient_id_counter
    if patient.email in patients_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    hashed_password = get_password_hash(patient.password)
    patient_dict = patient.dict()
    patient_dict['id'] = patient_id_counter
    patient_dict['created_at'] = datetime.now()
    patient_dict['password'] = hashed_password
    
    patients_db[patient.email] = patient_dict
    patient_id_counter += 1
    
    return patient_dict

@app.get("/patients/me", response_model=Patient)
async def read_patient_me(current_user: dict = Depends(get_current_user)):
    return current_user

@app.get("/patients/", response_model=List[Patient])
async def read_patients(_: dict = Depends(get_current_user)):
    return list(patients_db.values())

@app.put("/patients/{patient_id}", response_model=Patient)
async def update_patient(
    patient_id: int,
    patient_update: PatientBase,
    current_user: dict = Depends(get_current_user)
):
    if patient_id != current_user['id']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify other patient's data"
        )
    
    current_user.update(patient_update.dict(exclude_unset=True))
    return current_user