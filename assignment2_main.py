#!/usr/bin/env python
# coding: utf-8

# In[1]:


import re
from urllib.parse import unquote
import sqlite3
import hashlib
import html
import getpass


# In[2]:


class User:
    def __init__(self, db_path='online_shopping_database.db'):
        self.conn = sqlite3.connect(db_path)
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        # Create tables for users/customers and products
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          username TEXT NOT NULL,
                          password TEXT NOT NULL)''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS products (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          name TEXT NOT NULL,
                          price REAL NOT NULL)''')
        self.conn.commit()
        
    @staticmethod
    def sanitize_input(input_str):
        # Implement basic input sanitization to protect against SQL injection
        sanitized_str = re.sub(r"[;'\"-]", "", input_str)
        return sanitized_str
    
    @staticmethod
    def prevent_sql_injection(input_query):
        # Perform the SQL query using the sanitized input
        return User.sanitize_input(input_query)

    @staticmethod
    def prevent_xss(input_text):
        # Implement basic HTML escaping to protect against XSS attacks
        return html.escape(input_text)

    def user_exists(self, username):
        cursor = self.conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username=?", (username,))
        return cursor.fetchone() is not None
    
    def register_user(self, username, password):
        if self.user_exists(username):
            return "Username already exists. Please choose another one."
        
        # Sanitize and hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Sanitize the username
        sanitized_username = User.prevent_xss(username)

        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                       (sanitized_username, hashed_password))
        self.conn.commit()
        return "Registration successful. You can now log in to the online shopping system."

    def login_user(self, username, password):
        # Sanitize the username
        sanitized_username = User.prevent_xss(username)

        cursor = self.conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username=?", (sanitized_username,))
        row = cursor.fetchone()

        if row:
            stored_password = row[0]
            # Hash the provided password and compare it with the stored one
            if stored_password == hashlib.sha256(password.encode()).hexdigest():
                return "Login successful. Welcome, {}!".format(sanitized_username)

        return "Invalid username or password. Please try again."
    
    def search_product(self, query):
        # Prevent SQL Injection
        result = User.prevent_sql_injection(query)

        cursor = self.conn.cursor()
        cursor.execute("SELECT name, price FROM products WHERE name LIKE ?", ('%' + query + '%',))
        results = cursor.fetchall()

        if results:
            products = []
            for result in results:
                product_name, product_price = result
                products.append({
                    "name": product_name,
                    "price": product_price
                })
            return products

        return "No products matching the given query."

    def close_connection(self):
        self.conn.close()


# In[3]:


class Customer(User):
    def __init__(self, username, password, email, shipping_address):
        super().__init__()
        self.username = username
        self.password = password
        self.email = email
        self.shipping_address = shipping_address


# In[4]:


class WebApplicationFirewall:
    def __init__(self):
        self.sql_injection_patterns = ["SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "1=1"]
        self.xss_patterns = ["<script>","javascript:", "alert(", "onerror="]

    def detect_sql_injection(self, input_data):
        for pattern in self.sql_injection_patterns:
            if pattern.lower() in input_data.lower():
                return True
        return False

    def detect_xss(self, input_data):
        for pattern in self.xss_patterns:
            if pattern.lower() in input_data.lower():
                return True
        return False

    def protect(self, input_data):
        if self.detect_sql_injection(input_data):
            return "SQL Injection Detected! Request Blocked."
        elif self.detect_xss(input_data):
            return "XSS Attack Detected! Request Blocked."
        else:
            return "Request Passed WAF Security Check. Welcome to the online shopping system"


# In[5]:


# Test data sample for user activity
if __name__ == "__main__":
    cus = User()

    while True:
        print("\nWelcome to the online shopping System")
        print("1. Register")
        print("2. Login")
        print("3. Browse product catalog")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        if choice == "1":
            # Register a user
            username = input("Enter a new username: ")
            password = getpass.getpass("Enter a password: ")  # Securely get the password
            registration_result = cus.register_user(username, password)
            print(registration_result)
            
        elif choice == "2":
            # Log in user
            username = input("Enter your username: ")
            password = getpass.getpass("Enter your password: ")  # Securely get the password
            login_result = cus.login_user(username, password)
            print(login_result)
        elif choice == "3":
            # Search for products
            query = input("Enter a search query: ")
            search_result = cus.search_product(query)
            print(search_result)
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please choose again.")
    
    # Close the database connection when finished
    cus.close_connection()


# In[6]:


if __name__ == "__main__":
    customer = Customer("john wick", "password123", "john@example.com", "123 Main St, Beirut")
    registration_result = customer.register_user("john wick", "password123")
    print(registration_result)


# In[7]:


# Test data sample for WebApplicationFirewall
if __name__ == "__main__":
    waf = WebApplicationFirewall()

    # Simulated user input
    user_input_sql_injection = "SELECT * FROM users"
    user_input_xss = "<script>alert('XSS')</script>"
    safe_user_input = "Hello, World!"

    result_sql_injection = waf.protect(user_input_sql_injection)
    result_xss = waf.protect(user_input_xss)
    result_safe = waf.protect(safe_user_input)

    print(result_sql_injection)  # Output: SQL Injection Detected! Request Blocked.
    print(result_xss)  # Output: XSS Attack Detected! Request Blocked.
    print(result_safe)  # Output: Request Passed WAF Security Check. Welcome to the online shopping system


# In[ ]:




