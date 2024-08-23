# Trip Details Page
# API Endpoints:
                # GET /trips/{trip_id}: Get details of a specific trip, including itinerary, inclusions, exclusions, etc.
                # POST /trips/{trip_id}/book: Endpoint to initiate booking for the trip.
# Database Models:
# Booking: Fields might include id, trip_id, user_id, status, booking_date, payment_status, etc.







# class TripCreate(BaseModel):
#     title: str
#     description: str
#     price: float
#     location_id: int
#     image_url: Optional[str] = None

# class TripResponse(BaseModel):
#     id: int
#     title: str
#     description: str
#     price: float
#     location_id: int
#     image_url: Optional[str] = None

#     class Config:
#         orm_mode = True
