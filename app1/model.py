from .database import Base
from sqlalchemy import Column, Integer, String, ForeignKey, Float, DateTime, Boolean, Text
from sqlalchemy.dialects.mysql import LONGTEXT
# from sqlalchemy.orm import relationship
# from datetime import datetime

# # User Model
# class User1(Base):
#     __tablename__ = 'users'
    
#     id = Column(Integer, primary_key=True, autoincrement=True)
#     name = Column(String(100), nullable=False)
#     email = Column(String(100), unique=True, nullable=False)
#     phone = Column(String(15), nullable=True)
#     password_hash = Column(String(255), nullable=False)
    
#     bookings = relationship("Booking", back_populates="user")
#     payments = relationship("Payment", back_populates="user")
#     messages = relationship("ContactMessage", back_populates="user")
#     sessions = relationship("UserSession", back_populates="user")
#     notifications = relationship("Notification", back_populates="user")


# Create a model for storing user data and OTPs.

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    password = Column(LONGTEXT, nullable=False)
    is_active = Column(Boolean, default=False)
    role = Column(String(10))

    #Field for Forget Password Functionality
    otp_code = Column(String(6), nullable=True)
    otp_expires_at = Column(DateTime, nullable=True)

class UnverifiedUser(Base):
    __tablename__ = "unverified_users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    password = Column(LONGTEXT, nullable=False)
    role = Column(String(10), default="Customer")
    otp_code = Column(String(6), nullable=False)
    otp_expires_at = Column(DateTime, nullable=False)

# # Location Model
# class Location(Base):
#     __tablename__ = 'locations'
    
#     id = Column(Integer, primary_key=True, index=True)
#     name = Column(String(100), nullable=False)
#     country = Column(String(100), nullable=False)
#     image_url = Column(String(255), nullable=True)
    
#     trips = relationship("Trip", back_populates="location")

# # Trip Model
# class Trip(Base):
#     __tablename__ = 'trips'
    
#     id = Column(Integer, primary_key=True, index=True)
#     title = Column(String(255), nullable=False)
#     description = Column(Text, nullable=False)
#     price = Column(Float, nullable=False)
#     location_id = Column(Integer, ForeignKey('locations.id'), nullable=False)
#     image_url = Column(String(255), nullable=True)
    
#     location = relationship("Location", back_populates="trips")
#     bookings = relationship("Booking", back_populates="trip")

# # Booking Model
# class Booking(Base):
#     __tablename__ = 'bookings'
    
#     id = Column(Integer, primary_key=True, index=True)
#     trip_id = Column(Integer, ForeignKey('trips.id'), nullable=False)
#     user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
#     status = Column(String(50), nullable=False, default='pending')
#     booking_date = Column(DateTime, default=datetime.utcnow)
#     payment_status = Column(String(50), nullable=False, default='unpaid')
    
#     trip = relationship("Trip", back_populates="bookings")
#     user = relationship("User", back_populates="bookings")
#     payments = relationship("Payment", back_populates="booking")

# # Payment Model
# class Payment(Base):
#     __tablename__ = 'payments'
    
#     id = Column(Integer, primary_key=True, index=True)
#     booking_id = Column(Integer, ForeignKey('bookings.id'), nullable=False)
#     user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
#     amount = Column(Float, nullable=False)
#     payment_method = Column(String(50), nullable=False)
#     status = Column(String(50), nullable=False, default='pending')
#     payment_date = Column(DateTime, default=datetime.utcnow)
    
#     booking = relationship("Booking", back_populates="payments")
#     user = relationship("User", back_populates="payments")

# # ContactMessage Model
# class ContactMessage(Base):
#     __tablename__ = 'contact_messages'
    
#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
#     message = Column(Text, nullable=False)
#     status = Column(String(50), nullable=False, default='unread')
#     created_at = Column(DateTime, default=datetime.utcnow)
    
#     user = relationship("User", back_populates="messages")

# # UserSession Model
# class UserSession(Base):
#     __tablename__ = 'user_sessions'
    
#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
#     token = Column(String(255), nullable=False, unique=True)
#     expiry = Column(DateTime, nullable=False)
    
#     user = relationship("User", back_populates="sessions")

# # Notification Model
# class Notification(Base):
#     __tablename__ = 'notifications'
    
#     id = Column(Integer, primary_key=True, index=True)
#     user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
#     message = Column(Text, nullable=False)
#     type = Column(String(50), nullable=False)
#     is_read = Column(Boolean, default=False)
#     created_at = Column(DateTime, default=datetime.utcnow)
    
#     user = relationship("User", back_populates="notifications")