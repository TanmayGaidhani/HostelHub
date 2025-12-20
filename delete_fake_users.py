from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["messtrack"]
users = db["users"]

result = users.delete_many({
    "password": {"$regex": "^\\$2b\\$"}  # bcrypt hashed fake password
})

print(f"Deleted {result.deleted_count} fake users")
