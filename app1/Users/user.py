from fastapi import APIRouter, status, Depends, HTTPException, Cookie, BackgroundTasks
from app1 import model
from ..database import engine, SessionLocal
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Annotated, Optional
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from fastapi.responses import JSONResponse
import secrets
import random
import smtplib
from email.message import EmailMessage
from fastapi_utils.tasks import repeat_every

# Configuration and constants
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTE = 90
oauth2_bearer = OAuth2PasswordBearer(tokenUrl = "token")
model.Base.metadata.create_all(bind=engine)

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

# Password Hasing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Models
class CreateAccount(BaseModel):
    name: str
    email: str
    password: str  # Assuming this will be hashed before storing
    role: str | None = "Customer"

class CreateAccountResponse(BaseModel):
    message: str

class OTPVerify(BaseModel):
    email: str
    otp_code: str

class LoginUser(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# class UpdateAccount(BaseModel):
#     name: str
#     address: str

class CreateNewPassword(BaseModel):
    old_password: str
    new_password: str
    re_enter_new_password: str

class ForgetPassword(BaseModel):
    new_password: str
    re_enter_new_password: str

# Utility Functions
def generate_otp() -> str:
    return str(random.randint(100000, 999999))

def send_otp(to_mail: str, otp: str):
    try:
        # Set up the SMTP server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()

        # Login credentials
        from_mail = "amanmit38481490@gmail.com"
        app_password = "hghx fquo fvet lnke"  # Replace with your actual app-specific password

        # Login to the email account
        server.login(from_mail, app_password)

        # Compose the email
        msg = EmailMessage()
        msg["Subject"] = "OTP VERIFICATION"
        msg["From"] = from_mail
        msg["To"] = to_mail
        msg.set_content(f"Your OTP is: {otp}")

        # Send the email
        server.send_message(msg)
        print("OTP sent successfully!")

    except Exception as e:
        print(f"Failed to send OTP due to an error: {e}")

    finally:
        server.quit()


def authenticate_user(email: str, password: str, db: Session):
    user = db.query(model.User).filter(model.User.email == email).first()
    if not user:
        return False
    if not pwd_context.verify(password, user.password): # type: ignore
        return False
    return user

def create_access_token(email: str, user_id: int, role: str, expires_delta: timedelta):
    encode = {"sub": email, "id": user_id, "role": role}
    expire = datetime.utcnow() + expires_delta
    encode.update({"exp": expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

user_router = APIRouter(prefix="/api/user")

@user_router.post("/create/account/", response_model=CreateAccountResponse)
def create_account(user: CreateAccount, db: db_dependency, background_tasks: BackgroundTasks):
    
    # Check if the email is already registered in the main user table or unverified table
    db_user = db.query(model.User).filter(model.User.email == user.email).first()
    
    db_unverified_user = db.query(model.UnverifiedUser).filter(model.UnverifiedUser.email == user.email).first()

    if db_user or db_unverified_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    #Hash the password and generate OTP
    hashed_password = pwd_context.hash(user.password)
    otp_code = generate_otp()
    otp_expires_at = datetime.utcnow() + timedelta(minutes=15) # OTP expires in 15 minutes

    # Store the user in the Unverified table
    new_unverified_user = model.UnverifiedUser(
        name=user.name,
        email=user.email,
        password=hashed_password,
        role=user.role,
        otp_code=otp_code,
        otp_expires_at=otp_expires_at
    )
    db.add(new_unverified_user)
    db.commit()

    # Send OTP email in the background
    background_tasks.add_task(send_otp, user.email, otp_code)

    return {"message": "Account created successfully, please verify your email"}

@user_router.post("/verify_otp/")
def verify_otp(otp: OTPVerify, db: db_dependency):
    # Fetch the unverified user
    db_unverified_user = db.query(model.UnverifiedUser).filter(model.UnverifiedUser.email == otp.email, model.UnverifiedUser.otp_code == otp.otp_code).first()

    # db_otp = db.query(model.OTP).filter(model.OTP.email == otp.email, model.OTP.otp_code == otp.otp_code).first()
    
    if not db_unverified_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP or email")
    
    if db_unverified_user.otp_expires_at < datetime.utcnow():
        db.delete(db_unverified_user)
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP has expired. Please create your account again.")
    
    # Move the user to the main User table
    new_user = model.User(
        name = db_unverified_user.name,
        email = db_unverified_user.email,
        password = db_unverified_user.password,
        role = db_unverified_user.role,
        is_active = True
    )
    db.add(new_user)
    db.delete(db_unverified_user)
    db.commit()

    return {"message":"Account verified successfully"}

@user_router.post("/login", response_model=Token)
def Login_User(form_data: LoginUser, db: db_dependency):
    user = authenticate_user(form_data.email, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user")
    
    # Check if the user is active
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Please verify your email to activate your account")
    
    token = create_access_token(user.email, user.id, user.role, timedelta(minutes=30)) # type: ignore
    response = JSONResponse({"access_token": token, "token_type": "bearer"})
    response.set_cookie(key="token", value=token, httponly=True, path="/")
    return response

@user_router.on_event("startup")
@repeat_every(seconds=3600)  # Runs every hour
def cleanup_expired_unverified_users():
    with SessionLocal() as db:
        db.query(model.UnverifiedUser).filter(model.UnverifiedUser.otp_expires_at < datetime.utcnow()).delete()
        db.commit()

# Authentication Dependency
def get_current_user(token: str = Cookie(None)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub") # type: ignore
        user_id: int = payload.get("id") # type: ignore
        role: str = payload.get("role") # type: ignore
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user")
        return {"username": username, "id": user_id, "role": role}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate user")

user_dependency = Annotated[dict, Depends(get_current_user)]

# @user_router.put("/forget-password")
# def Forget_password(email:str, forget: ForgetPassword, otp: OTPVerify, user: user_dependency, db: db_dependency, background_tasks: BackgroundTasks):
#     db_user = db.query(model.User).filter(model.User.email == email).first()

#     if db_user is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
        
#     #Hash the password and generate OTP
#     hashed_password = pwd_context.hash(user.password)
#     otp_code = generate_otp()
#     otp_expires_at = datetime.utcnow() + timedelta(minutes=15) # OTP expires in 15 minutes
    
#     # Check if the new password is the same as the old one
#     if pwd_context.verify(user_data.password, db_user.password): #type: ignore
#         raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password cannot be the same as the old password")

#     if user_data.password is not None:
#         db_user.password = pwd_context.hash(user_data.password) # type: ignore

#     db.commit()
#     db.refresh(db_user)
#     return {"Update Password Successfull"}

@user_router.put("/Create/new/password/")
def create_new_password(create: CreateNewPassword, user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication Failed")
    
    if user.get("role") != "Customer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access Denied")
    
  # Retrieve the user from the database
    db_user = db.query(model.User).filter(model.User.id == user["id"]).first()
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
    
    # Verify the old password
    if not pwd_context.verify(create.old_password, db_user.password): #type: ignore
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Old password is incorrect")
    
    # Check that the new password is not the same as the old password
    if pwd_context.verify(create.new_password, db_user.password): #type: ignore
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password cannot be the same as the old password")
    
    # Ensure new passwords match
    if create.new_password != create.re_enter_new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New passwords do not match")
    
    # Hash and update the new password
    db_user.password = pwd_context.hash(create.new_password) #type: ignore
    
    db.commit()
    db.refresh(db_user)
    
    return {"detail": "New Password Update Successful"}

@user_router.put("/forget-password/")
def forget_password_step_1(email: str, db: db_dependency, background_tasks: BackgroundTasks):
    # Step 1: User submits email to receive OTP
    db_user = db.query(model.User).filter(model.User.email == email).first()

    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
    
    # Generate and store OTP
    otp_code = generate_otp()
    otp_expires_at = datetime.utcnow() + timedelta(minutes=15)  # OTP expires in 15 minutes

    # Store OTP and expiration time in a temporary table or the user table
    db_user.otp_code = otp_code
    db_user.otp_expires_at = otp_expires_at
    db.commit()

    # Send OTP email in the background
    background_tasks.add_task(send_otp, email, otp_code)

    return {"message": "OTP sent successfully. Please check your email."}

@user_router.put("/verify-otp-and-reset-password/")
def forget_password_step_2(email: str, otp: str, new_password: str, re_enter_new_password: str, db: db_dependency):
    # Step 2: Verify OTP and reset password
    db_user = db.query(model.User).filter(model.User.email == email).first()

    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")
    
    # Verify OTP
    if db_user.otp_code != otp:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP")
    
    if db_user.otp_expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP has expired")

    # Ensure new passwords match
    if new_password != re_enter_new_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New passwords do not match")
    
    # Check that the new password is not the same as the old password
    if pwd_context.verify(new_password, db_user.password):  # type: ignore
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password cannot be the same as the old password")

    # Hash and update the new password
    db_user.password = pwd_context.hash(new_password)  # type: ignore
    db_user.otp_code = None  # Clear OTP
    db_user.otp_expires_at = None  # Clear OTP expiration
    db.commit()

    return {"message": "Password reset successful"}































# @user_router.get("/users/{user_id}", response_model=UserResponse)
# def get_user(user_id: int, db: db_dependency):
#     user = db.query(model.User).filter(model.User.id == user_id).first()
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")
#     return user

# @user_router.put("/{user_id}/update-user")
# def Update_User(user_id: int, user_data: UpdateUser, user: user_dependency, db: db_dependency):
#     if user is None:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication Failed")
    
#     if user.get("role") != "Customer":
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access Denied")

#     db_user = db.query(model.User).filter(model.User.id == user_id).first()
#     if db_user is None:
#         raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")

#     # Update fields
#     if user_data.name is not None:
#         db_user.name = user_data.name # type: ignore
#     if user_data.address is not None:
#         db_user.address = user_data.address # type: ignore

#     db.commit()
#     db.refresh(db_user)
#     return {"Update successfull"}

# @user_router.delete("/{id}/delete")
# def Delete_User(id:int, user: user_dependency, db: db_dependency):  # type: ignore
#     if user is None:
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication Failed")
    
#     if user.get("role") != "Customer":
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access Denied")

#     db_user = db.query(model.User).filter(model.User.id == id).first()    # type: ignore

#     if db_user:
#         db.delete(db_user)
#         db.commit()
#         return {"msg": "User deleted successfully"}
#     raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User Not Found")