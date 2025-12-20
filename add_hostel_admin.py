from pymongo import MongoClient
from werkzeug.security import generate_password_hash

client = MongoClient("mongodb://localhost:27017/")  
db = client["messtrack"]
xadmin_collection = db["xadminlogin"]

email = "hosteladmin@hostelhub.ac.in"
plain_password = "messtrackadmin"


hashed_password = generate_password_hash(
    plain_password,
    method="pbkdf2:sha256",
    salt_length=16
)

xadmin_data = {
    "_id": "6834b88ae22ad3fba85e654a",
    "email": email,
    "password": hashed_password
}

xadmin_collection.replace_one({"_id": xadmin_data["_id"]}, xadmin_data, upsert=True)

print("X-Admin inserted/updated successfully!")
print("hosteladmin@hostelhub.ac.in")
print("messtrackadmin")