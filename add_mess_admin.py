from pymongo import MongoClient
from werkzeug.security import generate_password_hash


client = MongoClient("mongodb+srv://tanmaygaidhani:Tanmay%40890@cluster0.xwnlb7q.mongodb.net/atls?appName=Cluster0")  
db = client["atls"]
admin_collection = db["adminlogin"]


email = "messtrack@admin.com"
plain_password = "messtrackadmin"


hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256', salt_length=16)

admin_data = {
    "_id": "6834b88ae22ad3fba85e654a",
    "email": email,
    "password": hashed_password
}


admin_collection.replace_one({"_id": admin_data["_id"]}, admin_data, upsert=True)

print("Admin user inserted/updated successfully!")
print("messtrack@admin.com")
print("messtrackadmin")

