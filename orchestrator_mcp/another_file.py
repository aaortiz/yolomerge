import os
import subprocess
import sqlite3

# This file intentionally has some security issues for demonstration

# Potential security issue: Hardcoded credentials
DATABASE_USER = "admin"
password = "super_secret_password123"

def execute_command(cmd):
    """
    Execute a system command.
    Potential security issue: Command injection vulnerability
    """
    return os.system(cmd)

def query_database(query, params=None):
    """
    Execute a database query.
    Potential security issue: SQL injection if not used with parameters
    """
    conn = sqlite3.connect("example.db")
    cursor = conn.cursor()
    if params:
        return cursor.execute(query, params).fetchall()
    else:
        # Unsafe direct execution
        return cursor.execute(query).fetchall()

def process_user_input(user_input):
    """
    Process user-provided input.
    Potential security issue: Unsafe eval
    """
    # This is unsafe!
    result = eval(user_input)
    return result

def main():
    # Some demo operations
    print("System info:")
    execute_command("echo $PATH")
    
    # Database operations
    users = query_database("SELECT * FROM users WHERE name = '" + input("Enter name: ") + "'")
    print(f"Found {len(users)} users")
    
    # Calculator
    expression = input("Enter math expression: ")
    result = process_user_input(expression)
    print(f"Result: {result}")

if __name__ == "__main__":
    main()