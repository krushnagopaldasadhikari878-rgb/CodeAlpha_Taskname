import sqlite3
import os
# Secure credentials using environment variables
USERNAME = os.getenv("APP_USERNAME", "admin")
PASSWORD = os.getenv("APP_PASSWORD", "securepassword")

conn = sqlite3.connect("users.db")
cursor = conn.cursor()


username = input("Enter username: ")
password = input("Enter password: ")

# Secure parameterized query
query = "SELECT * FROM users WHERE username=? AND password=?"

print("\nExecuting secure query:")
print(query)

cursor.execute(query, (username, password))
result = cursor.fetchall()

# Weak authentication check
if username == USERNAME and password == PASSWORD:
    print("Login successful!")
else:
    print("Invalid credentials")

conn.close()