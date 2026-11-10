
import streamlit as st
import sqlite3
import hashlib
import secrets
import hmac

# -----------------------------
# PAGE CONFIGURATION
# -----------------------------

st.set_page_config(
    page_title="Secure Login System",
    page_icon="",
    layout="centered"
)

DB_NAME = "users.db"

# -----------------------------
# DATABASE CREATION
# -----------------------------

def create_database():
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# PASSWORD HASHING
# -----------------------------

def hash_password(password, salt):
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        600000
    )

    return password_hash.hex()


# -----------------------------
# USER REGISTRATION
# -----------------------------

def register_user(username, password):

    salt = secrets.token_bytes(16).hex()

    password_hash = hash_password(password, salt)

    try:
        conn = sqlite3.connect(DB_NAME)

        conn.execute(
            "INSERT INTO users VALUES (?, ?, ?)",
            (username, salt, password_hash)
        )

        conn.commit()
        conn.close()

        return True

    except sqlite3.IntegrityError:
        return False


# -----------------------------
# USER LOGIN
# -----------------------------

def login_user(username, password):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute(
        "SELECT salt, password_hash FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()

    conn.close()

    if user is None:
        return False

    salt, stored_hash = user

    entered_hash = hash_password(password, salt)

    return hmac.compare_digest(entered_hash, stored_hash)


# Initialize database
create_database()


# -----------------------------
# WEBPAGE DESIGN
# -----------------------------

st.title("Secure Login System")

st.write("")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False


# -----------------------------
# AFTER SUCCESSFUL LOGIN
# -----------------------------

if st.session_state.logged_in:

    st.success("Login Successful!")

    st.subheader("Welcome to the Application")

    st.write("You are securely authenticated.")

    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()


# -----------------------------
# LOGIN AND REGISTER PAGE
# -----------------------------

else:

    login_tab, register_tab = st.tabs(
        ["Login", "Register"]
    )

    # LOGIN
    with login_tab:

        st.subheader("User Login")

        with st.form("login_form"):

            username = st.text_input("Username")

            password = st.text_input(
                "Password",
                type="password"
            )

            login_button = st.form_submit_button(
                "Login"
            )

            if login_button:

                if login_user(username, password):

                    st.session_state.logged_in = True

                    st.success("Login successful!")

                    st.rerun()

                else:

                    st.error(
                        "Invalid username or password!"
                    )

    # REGISTRATION
    with register_tab:

        st.subheader("Create New Account")

        with st.form("register_form"):

            new_username = st.text_input(
                "Create Username"
            )

            new_password = st.text_input(
                "Create Password",
                type="password"
            )

            confirm_password = st.text_input(
                "Confirm Password",
                type="password"
            )

            register_button = st.form_submit_button(
                "Register"
            )

            if register_button:

                if not new_username or not new_password:

                    st.warning(
                        "Please fill in all fields."
                    )

                elif len(new_password) < 8:

                    st.warning(
                        "Password must contain at least 8 characters."
                    )

                elif new_password != confirm_password:

                    st.error(
                        "Passwords do not match!"
                    )

                else:

                    success = register_user(
                        new_username,
                        new_password
                    )

                    if success:

                        st.success(
                            "Account created successfully! Please login."
                        )

                    else:

                        st.error(
                            "Username already exists!"
                        )
