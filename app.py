"""
app.py
-------
Main Flask application for PhishGuard — a rule-based phishing risk
assessment tool.

Routes:
    GET  /                -> Home page
    POST /analyze/text    -> Analyze pasted text message
    POST /analyze/url     -> Analyze pasted URL
    POST /analyze/screenshot -> Analyze uploaded screenshot (OCR + text analysis)
    GET  /about           -> About page
    404 handler           -> Custom 404 page
    500 handler           -> Custom friendly error page
"""

import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, flash

from text_analysis import analyze_text, get_recommendations
from url_analysis import analyze_url, get_url_recommendations
from ocr_module import extract_text_from_image, allowed_file
from tips import get_random_tips

# ---------------------------------------------------------------------------
# APP CONFIGURATION
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
MAX_UPLOAD_SIZE_MB = 8

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE_MB * 1024 * 1024
app.secret_key = "phishguard-dev-secret-key"  # fine for a local educational project

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    """Render the home page with the three analysis option cards."""
    return render_template("index.html")


@app.route("/about")
def about():
    """Render the About page explaining how PhishGuard works."""
    return render_template("about.html")


@app.route("/analyze/text", methods=["POST"])
def analyze_text_route():
    """Handle pasted text message analysis."""
    message_text = request.form.get("message_text", "")

    analysis = analyze_text(message_text)

    if analysis["error"]:
        flash(analysis["error"])
        return redirect(url_for("home"))

    recommendations = get_recommendations(analysis["detected_indicators"])

    return render_template(
        "result.html",
        input_type="text",
        analyzed_text=message_text,
        analysis=analysis,
        recommendations=recommendations,
        tips=get_random_tips(5),
    )


@app.route("/analyze/url", methods=["POST"])
def analyze_url_route():
    """Handle pasted URL analysis."""
    url_input = request.form.get("url_input", "")

    analysis = analyze_url(url_input)

    if analysis["error"]:
        flash(analysis["error"])
        return redirect(url_for("home"))

    recommendations = get_url_recommendations(analysis["detected_indicators"])

    return render_template(
        "result.html",
        input_type="url",
        analyzed_url=url_input,
        analysis=analysis,
        recommendations=recommendations,
        tips=get_random_tips(5),
    )


@app.route("/analyze/screenshot", methods=["POST"])
def analyze_screenshot_route():
    """Handle screenshot upload: OCR extraction followed by text analysis."""
    if "screenshot" not in request.files:
        flash("No file was uploaded. Please choose a screenshot to analyze.")
        return redirect(url_for("home"))

    file = request.files["screenshot"]

    if file.filename == "":
        flash("No file was selected. Please choose a screenshot to analyze.")
        return redirect(url_for("home"))

    if not allowed_file(file.filename):
        flash("Invalid file type. Please upload a PNG, JPG, JPEG, BMP, or WEBP image.")
        return redirect(url_for("home"))

    # Save with a random filename to avoid collisions / path issues
    extension = file.filename.rsplit(".", 1)[1].lower()
    saved_filename = f"{uuid.uuid4().hex}.{extension}"
    saved_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_filename)

    try:
        file.save(saved_path)
    except Exception:
        flash("There was a problem saving your uploaded file. Please try again.")
        return redirect(url_for("home"))

    ocr_result = extract_text_from_image(saved_path)

    # Clean up the uploaded file after processing (we don't need to keep it)
    try:
        os.remove(saved_path)
    except OSError:
        pass

    if not ocr_result["success"]:
        flash(ocr_result["error"] or "Could not read text from the uploaded image.")
        return redirect(url_for("home"))

    extracted_text = ocr_result["text"]
    analysis = analyze_text(extracted_text)
    recommendations = get_recommendations(analysis["detected_indicators"])

    return render_template(
        "result.html",
        input_type="screenshot",
        extracted_text=extracted_text,
        analysis=analysis,
        recommendations=recommendations,
        tips=get_random_tips(5),
    )


# ---------------------------------------------------------------------------
# ERROR HANDLERS
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(413)
def file_too_large(e):
    flash(f"Uploaded file is too large. Maximum allowed size is {MAX_UPLOAD_SIZE_MB} MB.")
    return redirect(url_for("home"))


@app.errorhandler(500)
def internal_server_error(e):
    flash("Something went wrong on our end. Please try again.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)