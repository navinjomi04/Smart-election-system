from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from db import db_cursor, db_transaction
from ml_model import check_suspicious
from utils.csrf import regenerate_csrf_token, validate_csrf_form
from utils.datetime_helper import get_dt
from utils.security import generate_verification_code, generate_vote_hash, verify_password

bp = Blueprint("voter", __name__)


def _require_voter_session():
    if "user_id" not in session:
        return redirect(url_for("voter.voter_login"))
    return None


def _ensure_voter_freshness(voter_row):
    """Update session with fresh voter data to ensure UI (navbar) stays in sync."""
    if voter_row:
        session["voter_status"] = voter_row["status"]
        session["voter_name"] = voter_row["username"]


@bp.route("/voter_login", methods=["GET", "POST"])
def voter_login():
    if request.method == "POST":
        if not validate_csrf_form():
            flash("Invalid security token. Please try again.", "error")
            return redirect(url_for("voter.voter_login"))

        institution_code = request.form["institution_code"].strip()
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        with db_cursor() as cursor:
            cursor.execute(
                "SELECT * FROM elections WHERE institution_code=%s",
                (institution_code,),
            )
            election = cursor.fetchone()

            if not election:
                flash("Invalid Institution Code", "error")
                return redirect(url_for("voter.voter_login"))

            cursor.execute(
                """
                SELECT * FROM users
                WHERE username=%s AND election_id=%s
                """,
                (username, election["id"]),
            )
            user = cursor.fetchone()

            if user and verify_password(password, user["password"]):
                session["user_id"] = user["id"]
                _ensure_voter_freshness(user)
                session.pop("election_id", None)
                regenerate_csrf_token()

                if user["status"] == "pending":
                    flash("Your registration is pending admin approval.", "info")
                    return redirect(url_for("voter.voter_pending"))
                if user["status"] == "rejected":
                    flash("Your registration was not approved.", "error")
                    return redirect(url_for("voter.voter_rejected"))

                flash("Login successful", "success")
                return redirect(url_for("voter.voter_dashboard"))

            # Log failed voter login attempts
            ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
            ua = (request.headers.get("User-Agent") or "unknown")[:200]
            try:
                cursor.execute(
                    """
                    INSERT INTO logs (election_id, type, message)
                    VALUES (%s,%s,%s)
                    """,
                    (
                        election["id"],
                        "suspicious_login",
                        f"Failed voter login for username '{username}' from {ip} (UA: {ua})",
                    ),
                )
            except Exception:
                pass # Non-critical logging failure

            flash("Invalid credentials", "error")

    return render_template("voter_login.html")


@bp.route("/voter_pending")
def voter_pending():
    if "user_id" not in session:
        return redirect(url_for("voter.voter_login"))

    with db_cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
        voter = cursor.fetchone()

        if not voter:
            session.clear()
            return redirect(url_for("voter.voter_login"))
        
        _ensure_voter_freshness(voter)

        if voter["status"] == "approved":
            return redirect(url_for("voter.voter_dashboard"))
        if voter["status"] == "rejected":
            return redirect(url_for("voter.voter_rejected"))

        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (voter["election_id"],),
        )
        election = cursor.fetchone()

    return render_template(
        "voter_pending.html",
        username=voter["username"],
        election=election,
    )


@bp.route("/voter_rejected")
def voter_rejected():
    if "user_id" not in session:
        return redirect(url_for("voter.voter_login"))

    with db_cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
        voter = cursor.fetchone()

        if not voter:
            session.clear()
            return redirect(url_for("voter.voter_login"))
        
        _ensure_voter_freshness(voter)

        if voter["status"] != "rejected":
            if voter["status"] == "pending":
                return redirect(url_for("voter.voter_pending"))
            return redirect(url_for("voter.voter_dashboard"))

        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (voter["election_id"],),
        )
        election = cursor.fetchone()

    return render_template(
        "voter_rejected.html",
        username=voter["username"],
        election=election,
    )


@bp.route("/voter_dashboard")
def voter_dashboard():
    gate = _require_voter_session()
    if gate:
        return gate

    with db_cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
        voter = cursor.fetchone()

        if not voter:
            session.clear()
            return redirect(url_for("voter.voter_login"))

        _ensure_voter_freshness(voter)

        if voter["status"] == "pending":
            return redirect(url_for("voter.voter_pending"))
        if voter["status"] == "rejected":
            return redirect(url_for("voter.voter_rejected"))

        username = voter["username"]
        election_id = voter["election_id"]

        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (election_id,),
        )
        election = cursor.fetchone()

        election_name = election["institution_name"]

        now = datetime.now()
        start = get_dt(election["start_time"])
        end = get_dt(election["end_time"])

        if now < start:
            phase = "before"
            time_left = str(start - now).split(".")[0]

        elif now <= end:
            phase = "during"
            time_left = str(end - now).split(".")[0]

        else:
            phase = "after"
            time_left = "0:00:00"

        can_vote = (
            phase == "during"
            and voter["status"] == "approved"
            and voter["has_voted"] != 1
        )

    return render_template(
        "voter_dashboard.html",
        username=username,
        election_name=election_name,
        election=election,
        phase=phase,
        time_left=time_left,
        can_vote=can_vote,
        voter_status=voter["status"],
        has_voted=voter["has_voted"] == 1,
    )


@bp.route("/vote", methods=["GET", "POST"])
def vote():
    gate = _require_voter_session()
    if gate:
        return gate

    message = None
    verification_code = None
    candidates = []
    step = "choose"
    selected_name = None
    candidate_id_preview = None
    election = None

    if request.method == "POST" and not validate_csrf_form():
        flash("Invalid security token. Please try again.", "error")
        return redirect(url_for("voter.vote"))

    try:
        with db_cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
            voter = cursor.fetchone()

            if not voter:
                session.clear()
                return redirect(url_for("voter.voter_login"))

            if voter["status"] == "pending":
                return redirect(url_for("voter.voter_pending"))
            if voter["status"] == "rejected":
                return redirect(url_for("voter.voter_rejected"))

            election_id = voter["election_id"]
            cursor.execute(
                "SELECT * FROM elections WHERE id=%s",
                (election_id,),
            )
            election = cursor.fetchone()

            now = datetime.now()
            start = datetime.fromisoformat(str(election["start_time"]))
            end = datetime.fromisoformat(str(election["end_time"]))

            if now < start:
                message = "Voting has not started yet."
                step = "blocked"
            elif now > end:
                message = "Voting has ended."
                step = "blocked"
            elif voter["status"] != "approved":
                message = "You are not approved to vote."
                step = "blocked"
            elif voter["has_voted"] == 1:
                message = "You have already voted."
                step = "blocked"
            else:
                cursor.execute(
                    "SELECT id, name FROM candidates WHERE election_id=%s",
                    (election_id,),
                )
                candidates = cursor.fetchall()

                if not candidates:
                    message = "No candidates are configured for this election."
                    step = "blocked"
                elif request.method == "POST":
                    candidate_id = request.form.get("candidate_id")
                    confirm = request.form.get("confirm_vote")

                    if confirm == "1" and candidate_id:
                        try:
                            _process_vote_transaction(
                                voter=voter,
                                election_id=election_id,
                                candidate_id=candidate_id,
                            )
                            verification_code = session.pop(
                                "_last_verification_code", None
                            )
                            message = "Vote cast successfully."
                            step = "done"
                            candidates = []
                        except RuntimeError:
                            message = (
                                "Could not record your vote. "
                                "You may have already voted—please refresh."
                            )
                            step = "choose"
                    elif candidate_id:
                        cursor.execute(
                            """
                            SELECT name FROM candidates
                            WHERE id=%s AND election_id=%s
                            """,
                            (candidate_id, election_id),
                        )
                        row = cursor.fetchone()
                        if not row:
                            message = "Invalid candidate selection."
                            step = "choose"
                        else:
                            step = "confirm"
                            selected_name = row["name"]
                            candidate_id_preview = candidate_id

    except Exception as exc:
        print(f"Vote flow error: {exc}")
        message = "An error occurred processing your vote. Please try again."
        step = "choose"

    return render_template(
        "vote.html",
        election=election,
        candidates=candidates,
        message=message,
        verification_code=verification_code,
        step=step,
        selected_name=selected_name,
        candidate_id_preview=candidate_id_preview,
    )


def _process_vote_transaction(voter, election_id, candidate_id):
    verification_code = generate_verification_code()

    with db_transaction() as cursor:
        cursor.execute(
            "SELECT * FROM users WHERE id=%s FOR UPDATE",
            (voter["id"],),
        )
        locked = cursor.fetchone()

        if (
            not locked
            or locked["has_voted"] == 1
            or locked["status"] != "approved"
        ):
            raise RuntimeError("vote_not_allowed")

        cursor.execute(
            """
            SELECT id FROM candidates WHERE id=%s AND election_id=%s
            """,
            (candidate_id, election_id),
        )
        if not cursor.fetchone():
            raise RuntimeError("bad_candidate")

        cursor.execute(
            """
            SELECT vote_hash FROM votes
            WHERE election_id=%s
            ORDER BY id DESC LIMIT 1
            """,
            (election_id,),
        )
        prev = cursor.fetchone()
        previous_hash = prev["vote_hash"] if prev and prev.get("vote_hash") else "0"

        vote_hash = generate_vote_hash(voter["id"], candidate_id, previous_hash)

        suspicious = check_suspicious(voter["id"], candidate_id)
        log_type = "suspicious_login" if suspicious else "success"
        log_msg = (
            "Suspicious vote attempt"
            if suspicious
            else f"Vote cast by user {voter['username']}"
        )

        cursor.execute(
            """
            INSERT INTO votes (election_id, candidate_id, vote_hash, previous_hash, verification_code)
            VALUES (%s,%s,%s,%s,%s)
            """,
            (
                election_id,
                candidate_id,
                vote_hash,
                previous_hash,
                verification_code,
            ),
        )

        cursor.execute(
            "UPDATE users SET has_voted=1 WHERE id=%s",
            (voter["id"],),
        )

        cursor.execute(
            """
            INSERT INTO logs (election_id, type, message)
            VALUES (%s,%s,%s)
            """,
            (election_id, log_type, log_msg),
        )

    session["_last_verification_code"] = verification_code


@bp.route("/verify_vote", methods=["GET", "POST"])
def verify_vote():
    gate = _require_voter_session()
    if gate:
        return gate

    message = None
    verification_report = None
    submitted_code = None

    if request.method == "POST" and not validate_csrf_form():
        flash("Invalid security token. Please try again.", "error")
        return redirect(url_for("voter.verify_vote"))

    with db_cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
        voter = cursor.fetchone()
        if not voter:
            flash("Session invalid", "error")
            return redirect(url_for("voter.voter_login"))

        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (voter["election_id"],),
        )
        election = cursor.fetchone()
        if not election:
            flash("Election not found", "error")
            return redirect(url_for("voter.voter_dashboard"))

        now = datetime.now()
        start = get_dt(election["start_time"])
        end = get_dt(election["end_time"])

        if now < start:
            phase = "before"
        elif now <= end:
            phase = "during"
        else:
            phase = "after"

        if request.method == "POST":
            code = request.form["code"].strip()
            submitted_code = code

            cursor.execute(
                """
                SELECT v.*, c.name AS candidate_name
                FROM votes v
                LEFT JOIN candidates c ON v.candidate_id = c.id
                WHERE v.verification_code=%s AND v.election_id=%s
                """,
                (code, voter["election_id"]),
            )

            vote = cursor.fetchone()

            if vote:
                hash_status = (
                    "Chain metadata present"
                    if vote["vote_hash"] and vote["previous_hash"]
                    else "Incomplete hash metadata"
                )
                verification_report = {
                    "verification_code": code,
                    "status": "Verified",
                    "status_style": "verified",
                    "candidate_name": vote["candidate_name"] or "Unknown candidate",
                    "vote_hash": vote["vote_hash"] or "N/A",
                    "previous_hash": vote["previous_hash"] or "N/A",
                    "hash_status": hash_status,
                    "election_reference": election["institution_code"] or "N/A",
                    "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
                }
                message = "Vote verified successfully."
            else:
                message = "Invalid verification code."

    return render_template(
        "verify_vote.html",
        phase=phase,
        message=message,
        election=election,
        verification_report=verification_report,
        submitted_code=submitted_code,
        now=now.strftime("%Y-%m-%d %H:%M:%S"),
    )
