from pymongo import MongoClient
from faker import Faker
from bcrypt import hashpw, gensalt
import random

# Initialize faker with Indian locale
fake = Faker('en_IN')
Faker.seed(123)

# MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["messtrack"]
users = db["users"]

# Branches, Years, Gender lists
branches = ["CSE", "IT", "ECE", "MECH", "CIVIL", "AI&DS", "AIML", "Cybersecurity", "IOT"]
years = ["1", "2", "3", "4"]
genders = ["Male", "Female"]

# Function: Generate Indian mobile number (starting with 6-9)
def indian_mobile():
    return str(random.randint(6, 9)) + "".join([str(random.randint(0, 9)) for _ in range(9)])

# Function: Indian style email
def indian_email(name):
    name_part = name.lower().replace(" ", "")
    return f"{name_part}{random.randint(10,99)}@gmail.com"

# Create 500 fake users
for _ in range(500):
    name = fake.name()

    email = indian_email(name)
    username = name.split(" ")[0].lower() + str(random.randint(100,999))

    hashed_password = hashpw("password123".encode('utf-8'), gensalt()).decode('utf-8')

    user = {
        "name": name,
        "username": username,
        "password": hashed_password,
        "address": fake.address().replace("\n", ", "),  # Indian address
        "mobile_no": indian_mobile(),                    # Indian mobile number
        "email": email,                                  # Indian email pattern

        "academic_branch": random.choice(branches),
        "academic_year": random.choice(years),
        "gender": random.choice(genders),

        "status": "Approved",
        "confirmed": True,

        "user_type": "fake"  # Helps you delete fake users later
    }

    users.insert_one(user)

print("🎉 500 Indian Fake Students Inserted Successfully in messtrack.users")
