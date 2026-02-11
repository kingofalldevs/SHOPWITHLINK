import os
import re
import secrets
import random
import hashlib
from datetime import datetime, timedelta, timezone
from decimal import InvalidOperation

import requests
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    session,
    url_for,
    flash,
    abort,
    jsonify,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from models import db, User, Store, Product, Order, VerificationCode, Withdrawal

app = Flask(__name__, static_folder="static")
app.config.from_object(Config)
os.makedirs(Config.INSTANCE_PATH, exist_ok=True)
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def slugify(text):
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[-\s]+", "-", text)
    return text


def sanitize_description(description):
    """Remove API keys and secrets from descriptions before displaying."""
    if not description:
        return None
    # Check for common API key patterns (case-insensitive)
    api_key_patterns = ["SG.", "sk_", "pk_", "Bearer ", "API_KEY", "SECRET_KEY", "SENDGRID_API_KEY", "PAYSTACK"]
    description_upper = description.upper()
    for pattern in api_key_patterns:
        if pattern.upper() in description_upper:
            return None  # Hide description if it contains API key patterns
    return description


def get_cart(store_slug):
    """Get cart items for a store from session."""
    cart_key = f"cart_{store_slug}"
    return session.get(cart_key, [])


def add_to_cart(store_slug, product_id, product_name, product_price, product_image_url=None):
    """Add product to cart in session."""
    cart_key = f"cart_{store_slug}"
    cart = session.get(cart_key, [])
    
    # Check if product already in cart
    for item in cart:
        if item.get("product_id") == product_id:
            item["quantity"] = item.get("quantity", 1) + 1
            session[cart_key] = cart
            session.modified = True
            return True
    
    # Add new item
    cart.append({
        "product_id": product_id,
        "product_name": product_name,
        "product_price": float(product_price),
        "product_image_url": product_image_url,
        "quantity": 1,
    })
    session[cart_key] = cart
    session.modified = True
    return True


def remove_from_cart(store_slug, product_id):
    """Remove product from cart."""
    cart_key = f"cart_{store_slug}"
    cart = session.get(cart_key, [])
    cart = [item for item in cart if item.get("product_id") != product_id]
    session[cart_key] = cart
    session.modified = True
    return True


def clear_cart(store_slug):
    """Clear cart for a store."""
    cart_key = f"cart_{store_slug}"
    session.pop(cart_key, None)
    session.modified = True


def get_manage_token():
    """Token from query string or session."""
    return request.args.get("token") or session.get("store_manage_token")


def require_store_manage(store):
    """Allow if current user owns the store, or valid token (for legacy / link sharing)."""
    if current_user.is_authenticated and store.user_id == current_user.id:
        return
    token = get_manage_token()
    if token and token == store.secret_token:
        session["store_manage_token"] = store.secret_token
        return
    abort(403)


def store_manage_url(store):
    """URL for managing store (with token only for legacy stores)."""
    if current_user.is_authenticated and store.user_id == current_user.id:
        return url_for("store_manage", store_id=store.id)
    return url_for("store_manage", store_id=store.id, token=store.secret_token)


# OTP: 10 min expiry; code stored hashed (SHA-256 + salt), never plain text.
VERIFICATION_CODE_EXPIRY_MINUTES = 10
VERIFICATION_CODE_RESEND_COOLDOWN_SECONDS = 60


def _generate_verification_code(user):
    """Generate 6-digit OTP, store only its hash + salt; return plain code for email (never persisted)."""
    code = "".join(str(random.randint(0, 9)) for _ in range(6))
    salt = secrets.token_hex(32)
    code_hash = hashlib.sha256((salt + code).encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=VERIFICATION_CODE_EXPIRY_MINUTES)
    VerificationCode.query.filter_by(user_id=user.id).delete()
    vc = VerificationCode(user_id=user.id, code_hash=code_hash, salt=salt, expires_at=expires_at)
    db.session.add(vc)
    db.session.commit()
    return code


def _send_verification_email(user):
    """Send OTP via SendGrid v3 API (requests). Success on HTTP 200 or 202. Checks for sandbox mode and sender verification."""
    api_key = (app.config.get("SENDGRID_API_KEY") or "").strip()
    if not api_key:
        print("[SendGrid] ERROR: SENDGRID_API_KEY not set in .env")
        return False, "Email verification is not configured. Please set SENDGRID_API_KEY in .env"
    
    from_email = (app.config.get("SENDGRID_FROM_EMAIL") or "noreply@example.com").strip()
    from_name = (app.config.get("SENDGRID_FROM_NAME") or "Shop With Link").strip()
    to_email = user.email.strip()
    
    # Generate code AFTER validating config
    code = _generate_verification_code(user)
    
    subject = "Your verification code"
    plain_body = (
        f"Your verification code is: {code}\n"
        f"It expires in {VERIFICATION_CODE_EXPIRY_MINUTES} minutes.\n"
        "Do not share this code with anyone.\n"
        "If you didn't request this, ignore this email."
    )
    html_content = (
        f"<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>"
        f"<h2 style='color: #2563eb;'>Email Verification</h2>"
        f"<p>Your verification code is:</p>"
        f"<p style='font-size:32px;font-weight:bold;letter-spacing:8px;color:#1e40af;text-align:center;padding:20px;background:#eff6ff;border-radius:8px;'>{code}</p>"
        f"<p>It expires in <strong>{VERIFICATION_CODE_EXPIRY_MINUTES} minutes</strong>.</p>"
        f"<p><strong style='color:#dc2626;'>⚠️ Do not share this code</strong> with anyone.</p>"
        f"<p style='color:#6b7280;font-size:14px;'>If you didn't request this, you can safely ignore this email.</p>"
        f"</div>"
    )
    
    payload = {
        "personalizations": [{"to": [{"email": to_email}], "subject": subject}],
        "from": {"email": from_email, "name": from_name},
        "content": [
            {"type": "text/plain", "value": plain_body},
            {"type": "text/html", "value": html_content},
        ],
    }
    
    print(f"[SendGrid] Preparing to send email...")
    print(f"  From: {from_email} ({from_name})")
    print(f"  To: {to_email}")
    print(f"  Subject: {subject}")
    
    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=15,
        )
        
        status = resp.status_code
        body = resp.text
        headers = dict(resp.headers)
        
        print(f"[SendGrid] Response status: {status}")
        print(f"[SendGrid] Response headers: {headers}")
        
        # Check for sandbox mode warning in headers
        if "x-message-id" in headers:
            print(f"[SendGrid] Message ID: {headers['x-message-id']}")
        
        if status in (200, 202):
            print(f"[SendGrid] ✅ Email queued successfully (status {status})")
            print(f"[SendGrid] ⚠️  IMPORTANT: If email doesn't arrive:")
            print(f"    1. Check spam/junk folder")
            print(f"    2. Verify '{from_email}' is verified in SendGrid:")
            print(f"       → https://app.sendgrid.com/settings/sender_auth/senders/new")
            print(f"    3. Check SendGrid Activity Feed:")
            print(f"       → https://app.sendgrid.com/activity")
            print(f"    4. Ensure SendGrid account is NOT in sandbox mode")
            print(f"       → https://app.sendgrid.com/settings/sandbox")
            return True, None
        
        # Parse error response
        print(f"[SendGrid] ❌ FAILED - Status: {status}")
        print(f"[SendGrid] Response body: {body[:500]}")
        
        try:
            data = resp.json()
            errors = data.get("errors", [])
            if errors:
                err_msg = errors[0].get("message", body) or body
                # Check for field-specific errors
                if isinstance(errors[0], dict) and "field" in errors[0]:
                    field = errors[0].get("field", "")
                    if "from" in field.lower() or "sender" in field.lower():
                        err_msg = f"Sender verification issue: {err_msg}"
            else:
                err_msg = data.get("message", body) or body
        except Exception:
            err_msg = body or f"SendGrid returned {status}"
        
        err_msg = err_msg[:500] if err_msg else f"SendGrid returned {status}"
        err_lower = err_msg.lower()
        
        # Specific error handling
        if status == 401:
            return False, (
                "❌ Invalid SendGrid API key. "
                "Check SENDGRID_API_KEY in .env. "
                "Get your key from: https://app.sendgrid.com/settings/api_keys"
            )
        
        if "sender" in err_lower or "identity" in err_lower or "verified" in err_lower or "from address" in err_lower:
            return False, (
                f"❌ Sender email '{from_email}' is not verified in SendGrid.\n\n"
                f"To fix:\n"
                f"1. Go to: https://app.sendgrid.com/settings/sender_auth/senders/new\n"
                f"2. Add and verify: {from_email}\n"
                f"3. Check your email inbox for verification link\n"
                f"4. Click the link to verify\n\n"
                f"Until verified, SendGrid will NOT deliver emails."
            )
        
        if "sandbox" in err_lower:
            return False, (
                "❌ SendGrid is in SANDBOX MODE. Emails will NOT be delivered.\n\n"
                "To fix:\n"
                "1. Go to: https://app.sendgrid.com/settings/sandbox\n"
                "2. Disable sandbox mode\n"
                "3. Verify your sender email\n"
                "4. Try again"
            )
        
        return False, f"SendGrid error: {err_msg}"
        
    except requests.Timeout:
        print("[SendGrid] ❌ Request timeout")
        return False, "SendGrid request timed out. Check your internet connection."
    except requests.RequestException as e:
        print(f"[SendGrid] ❌ Request error: {e}")
        return False, f"Network error: {str(e)}. Check internet connection and try again."
    except Exception as e:
        print(f"[SendGrid] ❌ Unexpected error: {e}")
        return False, f"Unexpected error: {str(e)}"


def _verify_submitted_code(user, submitted_code):
    """Verify OTP: constant-time compare hash(salt + submitted) to stored code_hash; check expiry."""
    if not submitted_code or len(submitted_code) != 6 or not submitted_code.isdigit():
        return False
    vc = VerificationCode.query.filter_by(user_id=user.id).order_by(VerificationCode.created_at.desc()).first()
    if not vc:
        return False
    # SQLite returns naive datetimes; convert to UTC-aware for comparison.
    expires_at = vc.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        return False
    submitted_hash = hashlib.sha256((vc.salt + submitted_code).encode()).hexdigest()
    return submitted_hash == vc.code_hash


def _send_email_via_sendgrid(to_email, subject, html_content, plain_content):
    """Generic SendGrid email sender. Returns (success: bool, error_message: str)."""
    api_key = (app.config.get("SENDGRID_API_KEY") or "").strip()
    if not api_key:
        return False, "SendGrid API key not configured"
    
    from_email = (app.config.get("SENDGRID_FROM_EMAIL") or "noreply@example.com").strip()
    from_name = (app.config.get("SENDGRID_FROM_NAME") or "Shop With Link").strip()
    
    payload = {
        "personalizations": [{"to": [{"email": to_email}], "subject": subject}],
        "from": {"email": from_email, "name": from_name},
        "content": [
            {"type": "text/plain", "value": plain_content},
            {"type": "text/html", "value": html_content},
        ],
    }
    
    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            json=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=15,
        )
        
        if resp.status_code in (200, 202):
            return True, None
        return False, f"SendGrid returned {resp.status_code}"
    except Exception as e:
        return False, str(e)


def _send_order_confirmation_email(order, is_customer=True):
    """Send order confirmation email to customer or store owner."""
    store = order.store
    order_date = order.paid_at.strftime("%B %d, %Y at %I:%M %p") if order.paid_at else order.created_at.strftime("%B %d, %Y at %I:%M %p")
    
    if is_customer:
        to_email = order.customer_email
        subject = f"Order Confirmation - {order.product_name} from {store.name}"
        
        html_content = (
            f"<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>"
            f"<h2 style='color: #10b981;'>✅ Payment Confirmed!</h2>"
            f"<p>Thank you for your purchase, <strong>{order.customer_name}</strong>!</p>"
            f"<div style='background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;'>"
            f"<h3 style='margin-top: 0; color: #1e40af;'>Order Details</h3>"
            f"<p><strong>Order Reference:</strong> {order.paystack_reference}</p>"
            f"<p><strong>Product:</strong> {order.product_name}</p>"
            f"<p><strong>Quantity:</strong> {order.quantity}</p>"
            f"<p><strong>Amount Paid:</strong> ₵{order.amount:.2f}</p>"
            f"<p><strong>Store:</strong> {store.name}</p>"
            f"<p><strong>Order Date:</strong> {order_date}</p>"
            f"</div>"
            f"<p style='background: #eff6ff; padding: 15px; border-radius: 8px; border-left: 4px solid #2563eb;'>"
            f"<strong>What's next?</strong><br>"
            f"The store owner has been notified and will get in touch with you shortly to confirm delivery details."
            f"</p>"
            f"<p style='color: #6b7280; font-size: 14px; margin-top: 30px;'>"
            f"If you have any questions, please contact the store owner directly."
            f"</p>"
            f"</div>"
        )
        
        plain_content = (
            f"Payment Confirmed!\n\n"
            f"Thank you for your purchase, {order.customer_name}!\n\n"
            f"Order Details:\n"
            f"Order Reference: {order.paystack_reference}\n"
            f"Product: {order.product_name}\n"
            f"Quantity: {order.quantity}\n"
            f"Amount Paid: ₵{order.amount:.2f}\n"
            f"Store: {store.name}\n"
            f"Order Date: {order_date}\n\n"
            f"What's next?\n"
            f"The store owner has been notified and will get in touch with you shortly to confirm delivery details.\n\n"
            f"If you have any questions, please contact the store owner directly."
        )
    else:
        # Store owner email
        if not store.owner or not store.owner.email:
            return False, "Store owner email not found"
        
        to_email = store.owner.email
        subject = f"New Order Received - {order.product_name} from {store.name}"
        
        html_content = (
            f"<div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>"
            f"<h2 style='color: #2563eb;'>💰 New Order Received!</h2>"
            f"<p>You have received a new order for your store <strong>{store.name}</strong>.</p>"
            f"<div style='background: #eff6ff; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #2563eb;'>"
            f"<h3 style='margin-top: 0; color: #1e40af;'>Order Information</h3>"
            f"<p><strong>Order Reference:</strong> {order.paystack_reference}</p>"
            f"<p><strong>Product:</strong> {order.product_name}</p>"
            f"<p><strong>Quantity:</strong> {order.quantity}</p>"
            f"<p><strong>Amount:</strong> ₵{order.amount:.2f}</p>"
            f"<p><strong>Order Date:</strong> {order_date}</p>"
            f"</div>"
            f"<div style='background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;'>"
            f"<h3 style='margin-top: 0; color: #1e40af;'>Customer Information</h3>"
            f"<p><strong>Name:</strong> {order.customer_name}</p>"
            f"<p><strong>Email:</strong> {order.customer_email}</p>"
            f"{f'<p><strong>Phone:</strong> {order.customer_phone}</p>' if order.customer_phone else ''}"
            f"</div>"
            f"<p style='background: #fef3c7; padding: 15px; border-radius: 8px; border-left: 4px solid #f59e0b;'>"
            f"<strong>Action Required:</strong><br>"
            f"Please contact the customer to confirm delivery details. Once delivered, mark the order as delivered in your store dashboard."
            f"</p>"
            f"<p style='margin-top: 20px;'>"
            f"<a href='{url_for('store_overview', store_id=store.id, _external=True)}' "
            f"style='background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block;'>"
            f"View Order in Dashboard</a>"
            f"</p>"
            f"</div>"
        )
        
        plain_content = (
            f"New Order Received!\n\n"
            f"You have received a new order for your store {store.name}.\n\n"
            f"Order Information:\n"
            f"Order Reference: {order.paystack_reference}\n"
            f"Product: {order.product_name}\n"
            f"Quantity: {order.quantity}\n"
            f"Amount: ₵{order.amount:.2f}\n"
            f"Order Date: {order_date}\n\n"
            f"Customer Information:\n"
            f"Name: {order.customer_name}\n"
            f"Email: {order.customer_email}\n"
            f"{f'Phone: {order.customer_phone}\n' if order.customer_phone else ''}\n"
            f"Action Required:\n"
            f"Please contact the customer to confirm delivery details. Once delivered, mark the order as delivered in your store dashboard.\n\n"
            f"View order: {url_for('store_overview', store_id=store.id, _external=True)}"
        )
    
    return _send_email_via_sendgrid(to_email, subject, html_content, plain_content)


@app.route("/")
def index():
    """Landing page - redirect authenticated users to dashboard."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("register.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")
        user = User(email=email, password_hash=generate_password_hash(password), email_verified=False)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        ok, err = _send_verification_email(user)
        if ok:
            flash("Account created. Check your email for a verification code.")
        else:
            flash(f"Account created but we couldn't send the code: {err}. You can request a new code on the next page.", "error")
        return redirect(url_for("verify_email"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")
        login_user(user)
        if not user.email_verified:
            return redirect(url_for("verify_email"))
        next_url = request.args.get("next") or url_for("dashboard")
        return redirect(next_url)
    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("index"))


@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify_email():
    if current_user.email_verified:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        code = (request.form.get("code") or "").strip() or ((request.get_json(silent=True) or {}).get("code") or "").strip()
        if not code:
            if request.is_json:
                return {"ok": False, "error": "Code is required."}, 400
            flash("Enter the 6-digit code.", "error")
            return render_template("verify_email.html")
        if not _verify_submitted_code(current_user, code):
            if request.is_json:
                return {"ok": False, "error": "Invalid or expired code."}, 400
            flash("Invalid or expired code. Request a new one if needed.", "error")
            return render_template("verify_email.html")
        current_user.email_verified = True
        VerificationCode.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        if request.is_json:
            return {"ok": True, "message": "Email verified."}
        flash("Email verified. You're all set!")
        return redirect(url_for("dashboard"))
    return render_template("verify_email.html")


@app.route("/verify/send", methods=["POST"])
@login_required
def resend_verification():
    if current_user.email_verified:
        if request.is_json:
            return {"ok": True, "message": "Already verified."}
        return redirect(url_for("dashboard"))
    last = VerificationCode.query.filter_by(user_id=current_user.id).order_by(VerificationCode.created_at.desc()).first()
    if last:
        created_at = last.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - created_at).total_seconds() < VERIFICATION_CODE_RESEND_COOLDOWN_SECONDS:
            if request.is_json:
                return {"ok": False, "error": "Please wait a minute before requesting another code."}, 429
            flash("Please wait a minute before requesting another code.", "error")
            return redirect(url_for("verify_email"))
    ok, err = _send_verification_email(current_user)
    if request.is_json:
        if ok:
            return {"ok": True, "message": "Verification code sent."}
        return {"ok": False, "error": err or "Failed to send."}, 500
    if ok:
        flash("A new code has been sent to your email.")
    else:
        flash(f"Could not send code: {err}", "error")
    return redirect(url_for("verify_email"))


@app.route("/test-sendgrid", methods=["GET", "POST"])
@login_required
def test_sendgrid():
    """Test endpoint to diagnose SendGrid configuration issues."""
    if request.method == "POST":
        test_email = (request.form.get("test_email") or current_user.email).strip()
        if not test_email:
            flash("Please provide an email address.", "error")
            from_email = app.config.get("SENDGRID_FROM_EMAIL") or "not configured"
            return render_template("test_sendgrid.html", from_email=from_email)
        
        # Create a temporary user-like object for testing
        class TestUser:
            def __init__(self, email):
                self.email = email
                self.id = current_user.id
        
        test_user = TestUser(test_email)
        ok, err = _send_verification_email(test_user)
        
        if ok:
            flash(f"✅ Test email sent successfully to {test_email}! Check inbox (and spam folder).", "success")
        else:
            flash(f"❌ Failed to send test email: {err}", "error")
        
        from_email = app.config.get("SENDGRID_FROM_EMAIL") or "not configured"
        return render_template("test_sendgrid.html", test_email=test_email, result_ok=ok, result_error=err, from_email=from_email)
    
    return render_template("test_sendgrid.html")


@app.route("/dashboard")
@login_required
def dashboard():
    if not current_user.email_verified:
        return redirect(url_for("verify_email"))
    stores = current_user.stores.order_by(Store.created_at.desc()).all()
    return render_template("dashboard.html", stores=stores)


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/profile/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password") or ""
        new_password = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""
        if not check_password_hash(current_user.password_hash, current):
            flash("Current password is incorrect.", "error")
            return render_template("change_password.html")
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "error")
            return render_template("change_password.html")
        if new_password != confirm:
            flash("New passwords do not match.", "error")
            return render_template("change_password.html")
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash("Password updated successfully.")
        return redirect(url_for("profile"))
    return render_template("change_password.html")


@app.route("/orders")
@login_required
def orders_list():
    orders = (
        Order.query.filter(
            db.or_(Order.user_id == current_user.id, Order.customer_email == current_user.email)
        )
        .order_by(Order.created_at.desc())
        .all()
    )
    return render_template("orders.html", orders=orders)


@app.route("/store/<slug>/product/<int:product_id>/checkout", methods=["GET", "POST"])
def checkout(slug, product_id):
    """Checkout for single product (Buy Now)."""
    store = Store.query.filter_by(slug=slug).first_or_404()
    product = Product.query.filter_by(id=product_id, store_id=store.id).first_or_404()
    if request.method == "POST":
        name = (request.form.get("customer_name") or "").strip()
        email = (request.form.get("customer_email") or "").strip().lower()
        phone = (request.form.get("customer_phone") or "").strip() or None
        if not name or not email:
            flash("Name and email are required.", "error")
            return render_template("checkout.html", store=store, product=product)
        amount = float(product.price)
        if amount <= 0:
            flash("This product cannot be purchased.", "error")
            return redirect(url_for("store_public", slug=store.slug))
        # Paystack Ghana (GHS) minimum is ₵0.10 (10 pesewas)
        if amount < 0.10:
            flash("Minimum payment amount is ₵0.10 for Paystack.", "error")
            return render_template("checkout.html", store=store, product=product)
        reference = "ord_" + secrets.token_urlsafe(16)
        order = Order(
            user_id=current_user.id if current_user.is_authenticated else None,
            store_id=store.id,
            product_id=product.id,
            product_name=product.name,
            quantity=1,
            amount=product.price,
            currency="GHS",
            paystack_reference=reference,
            status="pending",
            customer_name=name,
            customer_email=email,
            customer_phone=phone,
        )
        db.session.add(order)
        db.session.commit()
        if not app.config.get("PAYSTACK_SECRET_KEY"):
            order.status = "paid"
            order.paid_at = datetime.now(timezone.utc)
            db.session.commit()
            
            # Send confirmation emails (testing mode)
            _send_order_confirmation_email(order, is_customer=True)
            if order.store.owner and order.store.owner.email:
                _send_order_confirmation_email(order, is_customer=False)
            
            flash("Payment is not configured. Order recorded for testing.")
            if current_user.is_authenticated:
                return redirect(url_for("orders_list"))
            return redirect(url_for("index"))
        paystack_url, err_msg = _paystack_initialize(order)
        if paystack_url:
            return redirect(paystack_url)
        flash(err_msg or "Could not start payment. Please try again.", "error")
        return render_template("checkout.html", store=store, product=product)
    return render_template("checkout.html", store=store, product=product)


@app.route("/store/<slug>/cart/checkout", methods=["GET", "POST"])
def cart_checkout(slug):
    """Checkout for entire cart."""
    store = Store.query.filter_by(slug=slug).first_or_404()
    cart_items = get_cart(store.slug)
    
    if not cart_items:
        flash("Your cart is empty.", "error")
        return redirect(url_for("store_cart", slug=store.slug))
    
    if request.method == "POST":
        name = (request.form.get("customer_name") or "").strip()
        email = (request.form.get("customer_email") or "").strip().lower()
        phone = (request.form.get("customer_phone") or "").strip() or None
        if not name or not email:
            flash("Name and email are required.", "error")
            total = sum(item.get("product_price", 0) * item.get("quantity", 1) for item in cart_items)
            return render_template("cart_checkout.html", store=store, cart_items=cart_items, total=total)
        
        total = sum(item.get("product_price", 0) * item.get("quantity", 1) for item in cart_items)
        if total <= 0:
            flash("Invalid cart total.", "error")
            return redirect(url_for("store_cart", slug=store.slug))
        
        if total < 0.10:
            flash("Minimum payment amount is ₵0.10 for Paystack.", "error")
            return render_template("cart_checkout.html", store=store, cart_items=cart_items, total=total)
        
        # Create orders for each cart item
        orders = []
        reference = "ord_" + secrets.token_urlsafe(16)
        
        for item in cart_items:
            product = Product.query.get(item.get("product_id"))
            if product:
                order = Order(
                    user_id=current_user.id if current_user.is_authenticated else None,
                    store_id=store.id,
                    product_id=product.id,
                    product_name=item.get("product_name", product.name),
                    quantity=item.get("quantity", 1),
                    amount=item.get("product_price", 0) * item.get("quantity", 1),
                    currency="GHS",
                    paystack_reference=f"{reference}_{product.id}",
                    status="pending",
                    customer_name=name,
                    customer_email=email,
                    customer_phone=phone,
                )
                db.session.add(order)
                orders.append(order)
        
        db.session.commit()
        
        if not app.config.get("PAYSTACK_SECRET_KEY"):
            for order_item in orders:
                order_item.status = "paid"
                order_item.paid_at = datetime.now(timezone.utc)
            db.session.commit()
            
            # Send confirmation emails (testing mode)
            # Send to customer (use first order)
            if orders:
                _send_order_confirmation_email(orders[0], is_customer=True)
                if orders[0].store.owner and orders[0].store.owner.email:
                    _send_order_confirmation_email(orders[0], is_customer=False)
            
            clear_cart(store.slug)
            flash("Payment is not configured. Orders recorded for testing.")
            if current_user.is_authenticated:
                return redirect(url_for("orders_list"))
            return redirect(url_for("index"))
        
        # Create a combined order for payment (single Paystack transaction)
        # Use first order but update amount to total
        main_order = orders[0]
        main_order.amount = total
        main_order.paystack_reference = reference  # Use base reference for payment
        db.session.commit()
        
        paystack_url, err_msg = _paystack_initialize(main_order)
        if paystack_url:
            # Store order references in session to mark all as paid after payment
            session[f"cart_orders_{reference}"] = [o.paystack_reference for o in orders]
            session.modified = True
            return redirect(paystack_url)
        flash(err_msg or "Could not start payment. Please try again.", "error")
    
    total = sum(item.get("product_price", 0) * item.get("quantity", 1) for item in cart_items)
    return render_template("cart_checkout.html", store=store, cart_items=cart_items, total=total)


def _paystack_initialize(order):
    """Initialize Paystack transaction; return (authorization_url or None, error_message)."""
    callback = url_for("payment_callback", _external=True)
    # Paystack Ghana: amount in pesewas (GHS × 100). Minimum ₵0.10 = 10 pesewas.
    amount_pesewas = int(float(order.amount) * 100)
    if amount_pesewas < 10:
        return None, "Amount must be at least ₵0.10."
    payload = {
        "email": order.customer_email,
        "amount": amount_pesewas,
        "currency": "GHS",
        "reference": order.paystack_reference,
        "callback_url": callback,
        "metadata": {"order_id": order.id},
    }
    try:
        resp = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers={
                "Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}",
                "Content-Type": "application/json",
            },
            timeout=15,
        )
        data = resp.json() if resp.content else {}
        if resp.ok and data.get("status") and data.get("data", {}).get("authorization_url"):
            return data["data"]["authorization_url"], None
        msg = data.get("message", "Paystack could not start the transaction.")
        app.logger.warning("Paystack initialize failed: %s %s", resp.status_code, data)
        return None, msg
    except requests.RequestException as e:
        app.logger.exception("Paystack request error")
        return None, "Payment service is temporarily unavailable. Please try again."


@app.route("/payment/callback")
def payment_callback():
    # Paystack redirects with ?reference=... (or sometimes trxref=...)
    reference = request.args.get("reference") or request.args.get("trxref")
    if not reference:
        flash("Invalid payment callback (no reference).", "error")
        return redirect(url_for("index"))
    order = Order.query.filter_by(paystack_reference=reference).first()
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("index"))
    if order.status == "paid":
        flash("Payment already recorded.")
        return _redirect_orders_or_index(order)
    if not app.config.get("PAYSTACK_SECRET_KEY"):
        flash("Payment is not configured. Order not updated.", "error")
        return _redirect_orders_or_index(order)
    try:
        resp = requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers={"Authorization": f"Bearer {app.config['PAYSTACK_SECRET_KEY']}"},
            timeout=15,
        )
        data = resp.json() if resp.content else {}
        if resp.ok and data.get("status") and data.get("data", {}).get("status") == "success":
            order.status = "paid"
            order.paid_at = datetime.now(timezone.utc)
            # Store credit is calculated dynamically (sum of paid orders - withdrawals)
            # No need to update balance field
            db.session.commit()
            
            # Check if this was a cart order
            cart_ref_key = f"cart_orders_{reference}"
            orders_to_notify = [order]  # List of orders to send emails for
            
            if cart_ref_key in session:
                # Mark all cart orders as paid
                order_refs = session.get(cart_ref_key, [])
                for ref in order_refs:
                    cart_order = Order.query.filter_by(paystack_reference=ref).first()
                    if cart_order:
                        cart_order.status = "paid"
                        cart_order.paid_at = datetime.now(timezone.utc)
                        orders_to_notify.append(cart_order)
                # Also mark the main payment order
                order.status = "paid"
                order.paid_at = datetime.now(timezone.utc)
                db.session.commit()
                # Clear cart
                clear_cart(order.store.slug)
                session.pop(cart_ref_key, None)
                session.modified = True
            else:
                # Single order
                db.session.commit()
            
            # Send confirmation emails
            # Send to customer (use first order for customer email)
            customer_email_sent = False
            for order_item in orders_to_notify:
                if not customer_email_sent:
                    ok, err = _send_order_confirmation_email(order_item, is_customer=True)
                    if ok:
                        customer_email_sent = True
                        print(f"[Email] Order confirmation sent to customer: {order_item.customer_email}")
                    else:
                        print(f"[Email] Failed to send customer confirmation: {err}")
            
            # Send to store owner (only once per store)
            if order.store.owner and order.store.owner.email:
                ok, err = _send_order_confirmation_email(order, is_customer=False)
                if ok:
                    print(f"[Email] Order notification sent to store owner: {order.store.owner.email}")
                else:
                    print(f"[Email] Failed to send store owner notification: {err}")
            
            # Show success message
            flash("✅ Payment successful! Your order has been received. We'll get in touch with you shortly.", "success")
            return redirect(url_for("payment_success", reference=reference))
        app.logger.warning("Paystack verify failed or not success: %s %s", resp.status_code, data)
    except requests.RequestException:
        app.logger.exception("Paystack verify request error")
    flash("Payment could not be verified. If you were charged, contact support with reference: " + reference[:20] + "...", "error")
    return _redirect_orders_or_index(order)


def _redirect_orders_or_index(order):
    if current_user.is_authenticated and (
        order.user_id == current_user.id or order.customer_email == current_user.email
    ):
        return redirect(url_for("orders_list"))
    return redirect(url_for("index"))


@app.route("/payment/success")
def payment_success():
    """Payment success page."""
    reference = request.args.get("reference")
    if not reference:
        return redirect(url_for("index"))
    
    order = Order.query.filter_by(paystack_reference=reference).first()
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("index"))
    
    store = order.store
    return render_template("payment_success.html", order=order, store=store)


@app.route("/store/new", methods=["GET", "POST"])
@login_required
def store_new():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        if not name:
            flash("Store name is required.", "error")
            return render_template("store_new.html")
        
        # Security: Prevent API keys from being saved as descriptions
        if description and sanitize_description(description) is None:
            flash("Invalid description. Please do not include API keys or secrets.", "error")
            return render_template("store_new.html")
        
        base_slug = slugify(name)
        slug = base_slug
        n = 0
        while Store.query.filter_by(slug=slug).first():
            n += 1
            slug = f"{base_slug}-{n}"
        store = Store(
            name=name,
            slug=slug,
            description=description or None,
            user_id=current_user.id,
        )
        db.session.add(store)
        db.session.commit()
        flash("Store created. You can now add products.")
        return redirect(url_for("store_overview", store_id=store.id))
    return render_template("store_new.html")


@app.route("/store/<slug>")
def store_public(slug):
    store = Store.query.filter_by(slug=slug).first_or_404()
    products = store.products.order_by(Product.created_at.desc()).all()
    
    # Security: Filter out API keys from store description
    # Always sanitize, even if description seems safe
    safe_description = sanitize_description(store.description)
    
    # If description contains API key, also clear it from database
    if store.description and safe_description is None:
        # API key detected - clear it from database
        store.description = None
        db.session.commit()
    
    # Create a safe store object for template (prevents accidental exposure)
    class SafeStore:
        def __init__(self, store, safe_description):
            self.name = store.name
            self.slug = store.slug
            self.description = safe_description  # This will be None if API key detected
            self.id = store.id
    
    safe_store = SafeStore(store, safe_description)
    
    # Get cart items count for this store
    cart_items = get_cart(store.slug)
    cart_count = sum(item.get("quantity", 1) for item in cart_items)
    
    return render_template("store_public.html", store=safe_store, products=products, cart_count=cart_count)


@app.route("/store/<slug>/cart/add/<int:product_id>", methods=["POST"])
def add_to_cart_route(slug, product_id):
    """Add product to cart."""
    store = Store.query.filter_by(slug=slug).first_or_404()
    product = Product.query.filter_by(id=product_id, store_id=store.id).first_or_404()
    
    add_to_cart(store.slug, product.id, product.name, product.price, product.image_url)
    
    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        cart_items = get_cart(store.slug)
        cart_count = sum(item.get("quantity", 1) for item in cart_items)
        return jsonify({"success": True, "cart_count": cart_count, "message": "Added to cart"})
    
    flash(f"{product.name} added to cart!", "success")
    return redirect(url_for("store_public", slug=store.slug))


@app.route("/store/<slug>/cart/remove/<int:product_id>", methods=["POST"])
def remove_from_cart_route(slug, product_id):
    """Remove product from cart."""
    store = Store.query.filter_by(slug=slug).first_or_404()
    remove_from_cart(store.slug, product_id)
    
    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        cart_items = get_cart(store.slug)
        cart_count = sum(item.get("quantity", 1) for item in cart_items)
        return jsonify({"success": True, "cart_count": cart_count})
    
    flash("Item removed from cart.", "success")
    return redirect(url_for("store_cart", slug=store.slug))


@app.route("/store/<slug>/cart")
def store_cart(slug):
    """Cart page for the store."""
    store = Store.query.filter_by(slug=slug).first_or_404()
    safe_description = sanitize_description(store.description)
    
    class SafeStore:
        def __init__(self, store, safe_description):
            self.name = store.name
            self.slug = store.slug
            self.description = safe_description
            self.id = store.id
    
    safe_store = SafeStore(store, safe_description)
    
    # Get cart items
    cart_items = get_cart(store.slug)
    total = sum(item.get("product_price", 0) * item.get("quantity", 1) for item in cart_items)
    
    return render_template("store_cart.html", store=safe_store, cart_items=cart_items, total=total)


@app.route("/store/<slug>/about")
def store_about(slug):
    """About page for the store."""
    store = Store.query.filter_by(slug=slug).first_or_404()
    safe_description = sanitize_description(store.description)
    
    class SafeStore:
        def __init__(self, store, safe_description):
            self.name = store.name
            self.slug = store.slug
            self.description = safe_description
            self.id = store.id
    
    safe_store = SafeStore(store, safe_description)
    return render_template("store_about.html", store=safe_store)


@app.route("/store/<int:store_id>/overview")
@login_required
def store_overview(store_id):
    """Store overview dashboard with stats, orders, and balance."""
    store = Store.query.get_or_404(store_id)
    if store.user_id != current_user.id:
        abort(403)
    
    from datetime import date
    # Get today's start (naive datetime for SQLite comparison)
    today = date.today()
    today_start = datetime.combine(today, datetime.min.time())
    # Count orders created today (SQLite stores naive datetimes)
    today_orders = sum(1 for order in store.orders.all() 
                      if order.created_at and order.created_at.date() == today)
    
    # Get recent orders (last 20)
    recent_orders = store.orders.order_by(Order.created_at.desc()).limit(20).all()
    
    # Calculate total orders
    total_orders = store.orders.count()
    
    # Calculate available balance dynamically
    available_balance = store.calculate_balance()
    
    # Get recent withdrawals (last 10)
    recent_withdrawals = store.withdrawals.order_by(Withdrawal.created_at.desc()).limit(10).all()
    
    # Calculate total withdrawals
    total_withdrawals = store.withdrawals.count()
    total_withdrawn = sum(float(w.amount) for w in store.withdrawals.all())
    
    return render_template(
        "store_overview.html",
        store=store,
        today_orders=today_orders,
        total_orders=total_orders,
        recent_orders=recent_orders,
        available_balance=available_balance,
        recent_withdrawals=recent_withdrawals,
        total_withdrawals=total_withdrawals,
        total_withdrawn=total_withdrawn,
    )


@app.route("/store/<int:store_id>/orders")
@login_required
def store_orders(store_id):
    """View all orders for a store."""
    store = Store.query.get_or_404(store_id)
    if store.user_id != current_user.id:
        abort(403)
    
    orders = store.orders.order_by(Order.created_at.desc()).all()
    return render_template("store_orders.html", store=store, orders=orders)


@app.route("/store/<int:store_id>/orders/<int:order_id>/deliver", methods=["POST"])
@login_required
def mark_order_delivered(store_id, order_id):
    """Mark an order as delivered."""
    store = Store.query.get_or_404(store_id)
    if store.user_id != current_user.id:
        abort(403)
    order = Order.query.filter_by(id=order_id, store_id=store_id).first_or_404()
    if order.status != "paid":
        flash("Only paid orders can be marked as delivered.", "error")
        return redirect(url_for("store_overview", store_id=store.id))
    order.delivered_at = datetime.now(timezone.utc)
    db.session.commit()
    flash(f"Order #{order.id} marked as delivered.", "success")
    return redirect(url_for("store_overview", store_id=store.id))


@app.route("/store/<int:store_id>/withdraw", methods=["GET", "POST"])
@login_required
def store_withdraw(store_id):
    """Withdraw store balance."""
    store = Store.query.get_or_404(store_id)
    if store.user_id != current_user.id:
        abort(403)
    
    # Calculate available balance dynamically
    available_balance = store.calculate_balance()
    
    if request.method == "POST":
        amount_str = (request.form.get("amount") or "").strip()
        account_details = (request.form.get("account_details") or "").strip()
        
        if not amount_str or not account_details:
            flash("Amount and account details are required.", "error")
            return render_template("store_withdraw.html", store=store, available_balance=available_balance)
        
        try:
            from decimal import Decimal
            amount = Decimal(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            
            # Check available balance (sum of paid orders - withdrawals)
            if amount > available_balance:
                flash(f"Insufficient balance. Available: ₵{available_balance:.2f}", "error")
                return render_template("store_withdraw.html", store=store, available_balance=available_balance)
            
            # Create withdrawal record
            withdrawal = Withdrawal(
                store_id=store.id,
                amount=amount,
                account_details=account_details
            )
            db.session.add(withdrawal)
            db.session.commit()
            
            flash(f"Withdrawal request for ₵{amount:.2f} submitted. Account details: {account_details}", "success")
            return redirect(url_for("store_overview", store_id=store.id))
        except (ValueError, InvalidOperation):
            flash("Please enter a valid amount.", "error")
            return render_template("store_withdraw.html", store=store, available_balance=available_balance)
    
    return render_template("store_withdraw.html", store=store, available_balance=available_balance)


@app.route("/store/<int:store_id>/manage")
def store_manage(store_id):
    store = Store.query.get_or_404(store_id)
    require_store_manage(store)
    if not (current_user.is_authenticated and store.user_id == current_user.id):
        session["store_manage_token"] = store.secret_token
    products = store.products.order_by(Product.created_at.desc()).all()
    manage_url = (
        url_for("store_manage", store_id=store.id, token=store.secret_token, _external=True)
        if store.user_id is None
        else None
    )
    owner_managed = current_user.is_authenticated and store.user_id == current_user.id
    return render_template(
        "store_manage.html",
        store=store,
        products=products,
        manage_url=manage_url,
        owner_managed=owner_managed,
    )


@app.route("/store/<int:store_id>/products/add", methods=["GET", "POST"])
def product_add(store_id):
    store = Store.query.get_or_404(store_id)
    require_store_manage(store)
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        price_str = (request.form.get("price") or "").strip()
        image_url = (request.form.get("image_url") or "").strip() or None
        if not name:
            flash("Product name is required.", "error")
            return render_template("product_form.html", store=store, product=None, manage_base=store_manage_url(store))
        try:
            price = float(price_str) if price_str else 0
            if price < 0:
                raise ValueError("Price cannot be negative")
        except (ValueError, InvalidOperation):
            flash("Please enter a valid price.", "error")
            return render_template("product_form.html", store=store, product=None, manage_base=store_manage_url(store))
        product = Product(store_id=store.id, name=name, description=description or None, price=price, image_url=image_url)
        db.session.add(product)
        db.session.commit()
        flash("Product added.")
        return redirect(store_manage_url(store))
    return render_template("product_form.html", store=store, product=None, manage_base=store_manage_url(store))


@app.route("/store/<int:store_id>/products/<int:product_id>/edit", methods=["GET", "POST"])
def product_edit(store_id, product_id):
    store = Store.query.get_or_404(store_id)
    require_store_manage(store)
    product = Product.query.filter_by(id=product_id, store_id=store_id).first_or_404()
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        price_str = (request.form.get("price") or "").strip()
        image_url = (request.form.get("image_url") or "").strip() or None
        if not name:
            flash("Product name is required.", "error")
            return render_template("product_form.html", store=store, product=product, manage_base=store_manage_url(store))
        try:
            price = float(price_str) if price_str else 0
            if price < 0:
                raise ValueError("Price cannot be negative")
        except (ValueError, InvalidOperation):
            flash("Please enter a valid price.", "error")
            return render_template("product_form.html", store=store, product=product, manage_base=store_manage_url(store))
        product.name = name
        product.description = description or None
        product.price = price
        product.image_url = image_url
        db.session.commit()
        flash("Product updated.")
        return redirect(store_manage_url(store))
    return render_template("product_form.html", store=store, product=product, manage_base=store_manage_url(store))


@app.route("/store/<int:store_id>/products/<int:product_id>/delete", methods=["POST"])
def product_delete(store_id, product_id):
    store = Store.query.get_or_404(store_id)
    require_store_manage(store)
    product = Product.query.filter_by(id=product_id, store_id=store_id).first_or_404()
    db.session.delete(product)
    db.session.commit()
    flash("Product deleted.")
    return redirect(store_manage_url(store))


with app.app_context():
    db.create_all()
    # Migration: add user_id to stores if upgrading from pre-auth DB
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    if insp.has_table("stores"):
        cols = [c["name"] for c in insp.get_columns("stores")]
        if "user_id" not in cols:
            db.session.execute(text("ALTER TABLE stores ADD COLUMN user_id INTEGER REFERENCES users(id)"))
            db.session.commit()
    if insp.has_table("users"):
        cols = [c["name"] for c in insp.get_columns("users")]
        if "email_verified" not in cols:
            db.session.execute(text("ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0"))
            db.session.commit()
            db.session.execute(text("UPDATE users SET email_verified = 1"))
            db.session.commit()
    # OTP: migrate verification_codes from plain `code` to hashed code_hash + salt; drop old `code` column.
    if insp.has_table("verification_codes"):
        cols = [c["name"] for c in insp.get_columns("verification_codes")]
        if "code_hash" not in cols:
            db.session.execute(text("ALTER TABLE verification_codes ADD COLUMN code_hash VARCHAR(64)"))
            db.session.execute(text("ALTER TABLE verification_codes ADD COLUMN salt VARCHAR(64)"))
            db.session.commit()
            db.session.execute(text("DELETE FROM verification_codes"))
            db.session.commit()
        if "code" in cols:
            # SQLite 3.35+ supports DROP COLUMN; removes NOT NULL constraint so INSERT with code_hash/salt works.
            try:
                db.session.execute(text("ALTER TABLE verification_codes DROP COLUMN code"))
                db.session.commit()
            except Exception:
                db.session.rollback()
                # Fallback: recreate table without code (SQLite < 3.35 or DROP COLUMN failed).
                db.session.execute(text(
                    "CREATE TABLE verification_codes_new (id INTEGER NOT NULL PRIMARY KEY, "
                    "user_id INTEGER NOT NULL, code_hash VARCHAR(64) NOT NULL, salt VARCHAR(64) NOT NULL, "
                    "expires_at DATETIME NOT NULL, created_at DATETIME, FOREIGN KEY(user_id) REFERENCES users(id))"
                ))
                db.session.execute(text("INSERT INTO verification_codes_new (id, user_id, code_hash, salt, expires_at, created_at) SELECT id, user_id, code_hash, salt, expires_at, created_at FROM verification_codes WHERE code_hash IS NOT NULL"))
                db.session.execute(text("DROP TABLE verification_codes"))
                db.session.execute(text("ALTER TABLE verification_codes_new RENAME TO verification_codes"))
                db.session.commit()
    # Migration: add balance to stores
    if insp.has_table("stores"):
        cols = [c["name"] for c in insp.get_columns("stores")]
        if "balance" not in cols:
            db.session.execute(text("ALTER TABLE stores ADD COLUMN balance NUMERIC(12, 2) DEFAULT 0"))
            db.session.commit()
    # Migration: add delivered_at to orders
    if insp.has_table("orders"):
        cols = [c["name"] for c in insp.get_columns("orders")]
        if "delivered_at" not in cols:
            db.session.execute(text("ALTER TABLE orders ADD COLUMN delivered_at DATETIME"))
            db.session.commit()
    # Migration: create withdrawals table if it doesn't exist
    if not insp.has_table("withdrawals"):
        db.session.execute(text(
            "CREATE TABLE withdrawals ("
            "id INTEGER NOT NULL PRIMARY KEY, "
            "store_id INTEGER NOT NULL, "
            "amount NUMERIC(12, 2) NOT NULL, "
            "account_details TEXT NOT NULL, "
            "created_at DATETIME, "
            "FOREIGN KEY(store_id) REFERENCES stores(id))"
        ))
        db.session.commit()


if __name__ == "__main__":
    # Never expose config in production
    import os
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(debug=debug_mode, port=5000)
