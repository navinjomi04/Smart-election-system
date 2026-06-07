from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from db import db_cursor
from utils.csrf import regenerate_csrf_token, validate_csrf_form
from utils.datetime_helper import get_dt
from utils.security import verify_password

bp = Blueprint("admin", __name__)


def _require_election_session():
    if "election_id" not in session:
        return redirect(url_for("admin.admin_login"))
    return None


def _require_reports_available(election):
    now = datetime.now()
    start = get_dt(election["start_time"])
    end = get_dt(election["end_time"])
    if now <= end:
        flash("Reports are available only after the election has ended.", "warning")
        return redirect(url_for("admin.admin_dashboard"))
    return None


@bp.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if not validate_csrf_form():
            flash("Invalid security token. Please try again.", "error")
            return redirect(url_for("admin.admin_login"))

        institution_code = request.form["institution_code"].strip()
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        with db_cursor() as cursor:
            cursor.execute(
                """
                SELECT * FROM elections
                WHERE institution_code=%s AND admin_username=%s
                """,
                (institution_code, username),
            )
            row = cursor.fetchone()

            if row and verify_password(password, row["admin_password"]):
                session["election_id"] = row["id"]
                regenerate_csrf_token()
                session.pop("user_id", None)
                session.pop("voter_name", None)
                flash("Signed in successfully.", "success")
                return redirect(url_for("admin.admin_dashboard"))

        flash("Invalid credentials", "error")
        return redirect(url_for("admin.admin_login"))

    return render_template("admin_login.html")


@bp.route("/admin_dashboard")
def admin_dashboard():
    gate = _require_election_session()
    if gate:
        return gate

    with db_cursor() as cursor:
        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (session["election_id"],),
        )
        election = cursor.fetchone()
        e_id = election["id"]

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

        cursor.execute("SELECT * FROM users WHERE election_id=%s", (e_id,))
        users = cursor.fetchall()

        pending = [u for u in users if u["status"] == "pending"]
        approved = [u for u in users if u["status"] == "approved"]
        rejected = [u for u in users if u["status"] == "rejected"]

        # Count only approved voters as eligible/current voters
        approved_count = len(approved)
        pending_count = len(pending)
        rejected_count = len(rejected)
        total_voters = approved_count

        cursor.execute(
            "SELECT COUNT(*) AS total FROM votes WHERE election_id=%s",
            (e_id,),
        )
        total_votes = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT c.name, COUNT(v.id) AS vote_count
            FROM candidates c
            LEFT JOIN votes v ON c.id = v.candidate_id
            WHERE c.election_id=%s
            GROUP BY c.id
            """,
            (e_id,),
        )
        results = cursor.fetchall()

        winner = None
        tie = False
        tied_candidates = []
        leading_candidate = "—"

        if results:
            max_votes = max(r["vote_count"] for r in results)
            tied_candidates = [r["name"] for r in results if r["vote_count"] == max_votes]

            if len(tied_candidates) > 1:
                tie = True
                leading_candidate = "Tie"
            elif tied_candidates:
                winner = tied_candidates[0]
                leading_candidate = winner

        cursor.execute(
            "SELECT * FROM logs WHERE election_id=%s ORDER BY id DESC",
            (e_id,),
        )
        logs = cursor.fetchall()

    return render_template(
        "admin_dashboard.html",
        election=election,
        phase=phase,
        time_left=time_left,
        total_voters=total_voters,
        approved_count=approved_count,
        pending_count=pending_count,
        rejected_count=rejected_count,
        total_votes=total_votes,
        pending=pending,
        approved=approved,
        rejected=rejected,
        results=results,
        winner=winner,
        tie=tie,
        tied_candidates=tied_candidates,
        leading_candidate=leading_candidate,
        logs=logs,
    )


@bp.route("/approve_user/<int:user_id>", methods=["POST"])
def approve_user(user_id):
    gate = _require_election_session()
    if gate:
        return gate
    if not validate_csrf_form():
        flash("Invalid security token. Please try again.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    election_id = session["election_id"]
    with db_cursor() as cursor:
        cursor.execute(
            """
            UPDATE users SET status='approved'
            WHERE id=%s AND election_id=%s AND status='pending'
            """,
            (user_id, election_id),
        )
        if cursor.rowcount:
            flash("User approved.", "success")
        else:
            flash("Unable to approve user (not found or not pending).", "warning")
    return redirect(url_for("admin.admin_dashboard"))


@bp.route("/reject_user/<int:user_id>", methods=["POST"])
def reject_user(user_id):
    gate = _require_election_session()
    if gate:
        return gate
    if not validate_csrf_form():
        flash("Invalid security token. Please try again.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    election_id = session["election_id"]
    with db_cursor() as cursor:
        cursor.execute(
            """
            UPDATE users SET status='rejected'
            WHERE id=%s AND election_id=%s AND status='pending'
            """,
            (user_id, election_id),
        )
        if cursor.rowcount:
            flash("User rejected.", "success")
        else:
            flash("Unable to reject user (not found or not pending).", "warning")
    return redirect(url_for("admin.admin_dashboard"))


@bp.route("/bulk_pending_users", methods=["POST"])
def bulk_pending_users():
    gate = _require_election_session()
    if gate:
        return gate
    if not validate_csrf_form():
        flash("Invalid security token. Please try again.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    action = (request.form.get("action") or "").strip().lower()
    ids_raw = request.form.getlist("user_ids")
    try:
        uid_list = [int(x) for x in ids_raw]
    except ValueError:
        flash("Invalid selection.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    if not uid_list:
        flash("Select at least one voter.", "warning")
        return redirect(url_for("admin.admin_dashboard"))

    if action not in ("approve", "reject"):
        flash("Unknown action.", "error")
        return redirect(url_for("admin.admin_dashboard"))

    election_id = session["election_id"]
    placeholders = ",".join(["%s"] * len(uid_list))
    status = "approved" if action == "approve" else "rejected"

    with db_cursor() as cursor:
        sql = (
            "UPDATE users SET status=%s WHERE election_id=%s AND status='pending' "
            "AND id IN (" + placeholders + ")"
        )
        params = (status, election_id, *uid_list)
        cursor.execute(sql, params)

        if cursor.rowcount:
            flash(f"Updated {cursor.rowcount} voter(s).", "success")
        else:
            flash("No pending voters were updated.", "warning")

    return redirect(url_for("admin.admin_dashboard"))


@bp.route("/admin_report")
def admin_report():
    gate = _require_election_session()
    if gate:
        return gate

    with db_cursor() as cursor:
        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (session["election_id"],),
        )
        election = cursor.fetchone()
        report_gate = _require_reports_available(election)
        if report_gate:
            return report_gate
        e_id = election["id"]

        cursor.execute(
            """
            SELECT c.name, COUNT(v.id) AS vote_count
            FROM candidates c
            LEFT JOIN votes v ON c.id = v.candidate_id
            WHERE c.election_id=%s
            GROUP BY c.id
            """,
            (e_id,),
        )
        raw_results = cursor.fetchall()

        results = [{"name": r["name"], "votes": r["vote_count"]} for r in raw_results]

        cursor.execute("SELECT * FROM users WHERE election_id=%s", (e_id,))
        users = cursor.fetchall()

        approved = [u for u in users if u["status"] == "approved"]
        rejected = [u for u in users if u["status"] == "rejected"]

        cursor.execute(
            "SELECT * FROM logs WHERE election_id=%s ORDER BY id DESC",
            (e_id,),
        )
        logs = cursor.fetchall()

    return render_template(
        "admin_report.html",
        election=election,
        results=results,
        approved=approved,
        rejected=rejected,
        logs=logs,
    )


@bp.route("/report_logs")
def report_logs():
    gate = _require_election_session()
    if gate:
        return gate

    with db_cursor() as cursor:
        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (session["election_id"],),
        )
        election = cursor.fetchone()
        report_gate = _require_reports_available(election)
        if report_gate:
            return report_gate

        e_id = election["id"] if election else None

        logs = []
        approved_for_report = []
        rejected_for_report = []
        pending_for_report = []
        vote_count_for_report = 0
        if e_id:
            cursor.execute(
                "SELECT username, email, status FROM users WHERE election_id=%s",
                (e_id,),
            )
            all_users = cursor.fetchall()
            approved_for_report = [u for u in all_users if u["status"] == "approved"]
            rejected_for_report = [u for u in all_users if u["status"] == "rejected"]
            pending_for_report = [u for u in all_users if u["status"] == "pending"]

            cursor.execute(
                "SELECT COUNT(*) AS total FROM votes WHERE election_id=%s",
                (e_id,),
            )
            vote_count_for_report = cursor.fetchone()["total"]

            cursor.execute(
                "SELECT * FROM logs WHERE election_id=%s ORDER BY id DESC",
                (e_id,),
            )
            logs = cursor.fetchall()
            suspicious_logs = [l for l in logs if l["type"] == "suspicious_login"]

    return render_template(
        "report_logs.html",
        election=election,
        logs=logs,
        suspicious_logs=suspicious_logs,
        approved_for_report=approved_for_report,
        rejected_for_report=rejected_for_report,
        pending_for_report=pending_for_report,
        total_voters_participated=vote_count_for_report,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@bp.route("/report_results")
def report_results():
    gate = _require_election_session()
    if gate:
        return gate

    with db_cursor() as cursor:
        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (session["election_id"],),
        )
        election = cursor.fetchone()
        report_gate = _require_reports_available(election)
        if report_gate:
            return report_gate
        e_id = election["id"] if election else None

        results = []
        winner = None
        tie = False
        tied_candidates = []

        if e_id:
            cursor.execute(
                """
                SELECT c.name, COUNT(v.id) AS vote_count
                FROM candidates c
                LEFT JOIN votes v ON c.id = v.candidate_id
                WHERE c.election_id=%s
                GROUP BY c.id
                """,
                (e_id,),
            )

            results = cursor.fetchall()

            if results:
                max_votes = max(r["vote_count"] for r in results)
                tied_candidates = [
                    r["name"] for r in results if r["vote_count"] == max_votes
                ]

                if len(tied_candidates) > 1:
                    tie = True
                else:
                    winner = tied_candidates[0]

            cursor.execute(
                "SELECT COUNT(*) AS total FROM votes WHERE election_id=%s",
                (e_id,),
            )
            total_votes_row = cursor.fetchone()
            total_votes = total_votes_row["total"] if total_votes_row else 0
        else:
            total_votes = 0

    return render_template(
        "report_results.html",
        election=election,
        results=results,
        winner=winner,
        tie=tie,
        tied_candidates=tied_candidates,
        total_votes=total_votes,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@bp.route("/report_users")
def report_users():
    gate = _require_election_session()
    if gate:
        return gate

    with db_cursor() as cursor:
        cursor.execute(
            "SELECT * FROM elections WHERE id=%s",
            (session["election_id"],),
        )
        election = cursor.fetchone()
        report_gate = _require_reports_available(election)
        if report_gate:
            return report_gate
        e_id = election["id"] if election else None

        users = []
        if e_id:
            cursor.execute(
                "SELECT username, email, status FROM users WHERE election_id=%s",
                (e_id,),
            )
            users = cursor.fetchall()

    return render_template(
        "report_users.html",
        election=election,
        users=users,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
