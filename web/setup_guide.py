"""Read-only, admin-only rendering of the repository-controlled setup guide."""
from pathlib import Path
from flask import Blueprint, abort, current_app, render_template, session
from sqlalchemy.orm import Session
from web.backend_wizard import is_admin

blueprint = Blueprint("guide", __name__)


@blueprint.get("/admin/setup-guide")
def setup_guide():
    with Session(current_app.extensions["custos_engine"]) as db:
        if not is_admin(db, session.get("principal_id")):
            abort(403)
    import markdown
    source = Path(__file__).resolve().parents[1] / "docs/setup-guide.md"
    # Trusted repository content only; no request or database Markdown is rendered.
    html = markdown.markdown(source.read_text(encoding="utf-8"),
                             extensions=["fenced_code", "tables", "toc"])
    return render_template("setup_guide.html", guide_html=html)
