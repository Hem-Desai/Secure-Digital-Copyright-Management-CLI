import os
from src.init_db import init_database

def reset_database():
    """Reset and reinitialize the database"""
    # Remove existing database file
    db_path = "secure_dcm.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        
    # Remove session file if exists
    session_file = ".session"
    if os.path.exists(session_file):
        os.remove(session_file)
        
    # Initialize fresh database
    init_database()

if __name__ == "__main__":
    reset_database() 