import random
import re
import string
from datetime import datetime
from utils.datetime_helper import get_dt
from flask import Blueprint, flash, redirect, render_template, request, url_for

from db import db_cursor
from utils.csrf import regenerate_csrf_token, validate_csrf_form
from utils.security import hash_password

bp = Blueprint("public", __name__)


def generate_institution_code():
    return "INST-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def validate_institution_name(name):
    """Institution name must be at least 3 characters."""
    return len(name) >= 3


def validate_admin_username(username):
    """Admin username must follow firstname_secondname format (e.g., john_d)."""
    regex = r"^[a-zA-Z]{3,}[_][a-zA-Z]{1,}$"
    return re.match(regex, username) is not None


def validate_admin_password(password):
    """Admin password must be numeric and at least 4 digits."""
    return re.match(r"^\d{4,}$", password) is not None


def validate_candidate_name(name):
    """Candidate name must be alphabetic and at least 3 letters."""
    return re.match(r"^[a-zA-Z]{3,}$", name) is not None


def validate_voter_username(username):
    """Voter username must follow firstname_secondname format (e.g., sam_k)."""
    regex = r"^[a-zA-Z]{3,}[_][a-zA-Z]{1,}$"
    return re.match(regex, username) is not None


def validate_voter_email(email):
    """Email must be a Gmail address."""
    return email.endswith("@gmail.com")


def validate_voter_password(password):
    """Voter password must be numeric and at least 3 digits."""
    return re.match(r"^\d{3,}$", password) is not None


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf_form():
            flash("Invalid security token. Please try again.", "error")
            return redirect(url_for("public.register"))

        institution_code = request.form["institution_code"].strip()
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"].strip()

        # Validate voter username format
        if not validate_voter_username(username):
            flash("Username must follow format: firstname_secondname (e.g., sam_k, alex_r).", "error")
            return redirect(url_for("public.register"))

        # Validate email format (@gmail.com)
        if not validate_voter_email(email):
            flash("Email must be a Gmail address (e.g., sam@gmail.com).", "error")
            return redirect(url_for("public.register"))

        # Validate password format (numeric, min 3 digits)
        if not validate_voter_password(password):
            flash("Password must be numeric and at least 3 digits (e.g., 123, 4567).", "error")
            return redirect(url_for("public.register"))

        with db_cursor() as cursor:
            cursor.execute(
                "SELECT * FROM elections WHERE institution_code=%s",
                (institution_code,),
            )
            election = cursor.fetchone()

            if not election:
                flash("Invalid Institution Code", "error")
                return redirect(url_for("public.register"))

            now = datetime.now()
            start = get_dt(election["start_time"])

            if now >= start:
                flash("Registration closed", "warning")
                return redirect(url_for("public.register"))

            # Check if username or email already exists for this election
            cursor.execute(
                "SELECT id FROM users WHERE election_id=%s AND (username=%s OR email=%s)",
                (election["id"], username, email),
            )
            existing_user = cursor.fetchone()
            if existing_user:
                flash("User already exists", "error")
                return redirect(url_for("public.register"))

            try:
                cursor.execute(
                    """
                    INSERT INTO users (election_id, username, email, password, status)
                    VALUES (%s, %s, %s, %s, 'pending')
                    """,
                    (
                        election["id"],
                        username,
                        email,
                        hash_password(password),
                    ),
                )
                flash("Registration submitted successfully.", "success")
                return redirect(url_for("public.register_success"))

            except Exception:
                flash("Registration failed. Please try again.", "error")

        return redirect(url_for("public.register"))

    return render_template("register.html")


@bp.route("/register_success")
def register_success():
    return render_template("register_success.html")


@bp.route("/admin_setup", methods=["GET", "POST"])
def admin_setup():
    if request.method == "POST":
        if not validate_csrf_form():
            flash("Invalid security token. Please try again.", "error")
            return redirect(url_for("public.admin_setup"))

        institution_name = request.form["institution_name"].strip()
        start_time = request.form["start_time"]
        end_time = request.form["end_time"]
        admin_username = request.form["admin_username"].strip()
        admin_password = request.form["admin_password"]

        if not institution_name or not start_time or not end_time or not admin_username or not admin_password:
            flash("All fields are required.", "error")
            return redirect(url_for("public.admin_setup"))

        # Validate institution name (min 3 characters)
        if not validate_institution_name(institution_name):
            flash("Institution name must be at least 3 characters.", "error")
            return redirect(url_for("public.admin_setup"))

        if start_time >= end_time:
            flash("Start time must be before end time.", "error")
            return redirect(url_for("public.admin_setup"))

        # Validate admin username format
        if not validate_admin_username(admin_username):
            flash("Admin username must follow format: firstname_secondname (e.g., john_d).", "error")
            return redirect(url_for("public.admin_setup"))

        # Validate admin password format (numeric, min 4 digits)
        if not validate_admin_password(admin_password):
            flash("Admin password must be numeric and at least 4 digits (e.g., 1234).", "error")
            return redirect(url_for("public.admin_setup"))

        candidate_names = []
        candidate_fields = [
            key for key in request.form.keys()
            if key.startswith('candidate') and key[9:].isdigit()
        ]
        candidate_fields.sort(key=lambda k: int(k[9:]))

        for key in candidate_fields:
            raw = request.form.get(key, '') or ''
            name = raw.strip()
            if not name:
                flash('Please fill or remove all candidate fields before submitting the election setup.', 'error')
                return redirect(url_for('public.admin_setup'))
            
            # Validate candidate name format
            if not validate_candidate_name(name):
                flash('Candidate names must be at least 3 letters (e.g., john, sam, alex).', 'error')
                return redirect(url_for('public.admin_setup'))
            
            candidate_names.append(name)

        if len(candidate_names) < 2:
            flash('Add at least two candidates before creating an election.', 'error')
            return redirect(url_for('public.admin_setup'))

        code = generate_institution_code()

        with db_cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO elections
                (institution_name, institution_code, start_time, end_time, admin_username, admin_password)
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                (
                    institution_name,
                    code,
                    start_time,
                    end_time,
                    admin_username,
                    hash_password(admin_password),
                ),
            )

            election_id = cursor.lastrowid

            for name in candidate_names:
                cursor.execute(
                    """
                    INSERT INTO candidates (election_id, name)
                    VALUES (%s,%s)
                    """,
                    (election_id, name),
                )

        return render_template("admin_setup_success.html", code=code)

    return render_template("admin_setup.html")
