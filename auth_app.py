import streamlit as st
import sqlite3
from sqlite3 import Error
import bcrypt

st.set_page_config(page_title="Mass Mailer Application", page_icon="✉️")  # You can also add a favicon icon


# Custom CSS
st.markdown("""
    <style>
    body {
        background-color: white;
        color: #2C3E50;
    }
    .big-font {
        font-size: 30px !important;
        color: #3498DB;
    }
    .stButton > button {
        background-color: #3498DB;
        color: white;
        font-size: 18px;
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

# Title

# Rest of your app logic here...




# Function to create a connection to the SQLite database
def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('users.db') 
        return conn
    except Error as e:
        print(e)
    return conn

# Function to create a 'users' table
def create_table(conn):
    try:
        sql_create_users_table = """ CREATE TABLE IF NOT EXISTS users (
                                        id integer PRIMARY KEY,
                                        username text NOT NULL UNIQUE,
                                        password text NOT NULL
                                    ); """
        c = conn.cursor()
        c.execute(sql_create_users_table)
    except Error as e:
        print(e)

# Function to register a new user with hashed password
def register_user(conn, username, password):
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        sql = ''' INSERT INTO users(username,password)
                  VALUES(?,?) '''
        cur = conn.cursor()
        cur.execute(sql, (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

# Function to check user credentials during login
def authenticate_user(conn, username, password):
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cur.fetchone()

    if row:
        stored_password = row[0]
        return bcrypt.checkpw(password.encode('utf-8'), stored_password)
    return False

# Function to fetch and print all users from the 'users' table
def print_users(conn):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    rows = cur.fetchall()

    if rows:
        st.subheader("Registered Users")
        for row in rows:
            st.write(f"ID: {row[0]}, Username: {row[1]}")
    else:
        st.write("No users found in the database.")

# Function to update user details (username and/or password)
def update_user_details(conn, user_id, new_username=None, new_password=None):
    cur = conn.cursor()
    try:
        if new_username:
            cur.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
        if new_password:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cur.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user_id))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def delete_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return cur.rowcount > 0

def is_password_numeric(password):
    return password.isdigit()

def main():

    conn = create_connection()

    if conn is not None:
        create_table(conn)

    st.title("Welcome to the Mass Mailer  Application 😀")

    # st.markdown('<p class="big-font">Welcome to the Mass Mailer  Application 😀</p>', unsafe_allow_html=True)
    
    # Navigation
    menu = ["Login", "Register", "View Users", "Update User", "Delete User"]
    choice = st.sidebar.selectbox("Menu", menu)
    # menu = ["Login", "Register", "View Users", "Update User", "Delete User"]
    # choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Login":
        st.subheader("Login")
        
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if authenticate_user(conn, username, password):
                st.success(f"Welcome {username}!")
            else:
                st.error("Invalid username or password")

    elif choice == "Register":
        st.subheader("Create a New Account")
        
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Register"):
            if new_username and new_password and confirm_password:
                if new_password == confirm_password:
                    if is_password_numeric(new_password):
                        if register_user(conn, new_username, new_password):
                            st.success("Registration successful!")
                        else:
                            st.error("Username already exists!")
                    else:
                        st.error("Password should contain only numbers.")
                else:
                    st.error("Passwords do not match")
            else:
                st.warning("Please fill out all fields")

    elif choice == "View Users":
        st.subheader("View Registered Users")
        print_users(conn)

    elif choice == "Update User":
        st.subheader("Update User Details")
        
        user_id = st.number_input("User ID", min_value=1)
        new_username = st.text_input("New Username (Leave blank if not changing)")
        new_password = st.text_input("New Password (Leave blank if not changing)", type="password")
        confirm_new_password = st.text_input("Confirm New Password", type="password")

        if st.button("Update"):
            if new_password and new_password != confirm_new_password:
                st.error("Passwords do not match")
            elif new_password and not is_password_numeric(new_password):
                st.error("Password should contain only numbers.")
            else:
                if new_username or new_password:
                    if update_user_details(conn, user_id, new_username, new_password):
                        st.success("User details updated successfully!")
                    else:
                        st.error("Error updating details, username may already exist")
                else:
                    st.warning("Please fill in at least one field to update")

    elif choice == "Delete User":
        st.subheader("Delete User from MassmailerApplication")
        
        user_id_to_delete = st.number_input("User ID to delete", min_value=1)

        if st.button("Delete"):
            if delete_user(conn, user_id_to_delete):
                st.success("User deleted successfully!")
            else:
                st.error("User ID not found.")

    if conn:
        conn.close()

if __name__ == "__main__":
    main()
