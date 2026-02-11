from datetime import datetime
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
import hashlib
import secrets

db = SQLAlchemy()


def generate_token():
    return secrets.token_urlsafe(16)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    stores = db.relationship("Store", backref="owner", lazy="dynamic")
    verification_codes = db.relationship("VerificationCode", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.email}>"


class VerificationCode(db.Model):
    """OTP stored as SHA-256 hash with per-record salt; never store plain text."""
    __tablename__ = "verification_codes"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    code_hash = db.Column(db.String(64), nullable=False)  # sha256 hex
    salt = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<VerificationCode user_id={self.user_id}>"


class Store(db.Model):
    __tablename__ = "stores"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False, index=True)
    description = db.Column(db.Text)
    secret_token = db.Column(db.String(64), nullable=False, default=generate_token)
    balance = db.Column(db.Numeric(12, 2), nullable=False, default=0)  # Legacy field, use calculate_balance() instead
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    products = db.relationship("Product", backref="store", lazy="dynamic", cascade="all, delete-orphan")
    withdrawals = db.relationship("Withdrawal", backref="store", lazy="dynamic", cascade="all, delete-orphan")

    def calculate_balance(self):
        """Calculate available store credit: sum of paid orders - sum of withdrawals."""
        from decimal import Decimal
        # Sum of all paid orders
        paid_orders_total = sum(
            Decimal(str(order.amount)) 
            for order in self.orders.filter_by(status="paid").all()
        )
        # Sum of all withdrawals
        withdrawals_total = sum(
            Decimal(str(w.amount))
            for w in self.withdrawals.all()
        )
        return paid_orders_total - withdrawals_total

    def __repr__(self):
        return f"<Store {self.name}>"


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey("stores.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    image_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Product {self.name}>"


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    store_id = db.Column(db.Integer, db.ForeignKey("stores.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=True)
    product_name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    currency = db.Column(db.String(3), nullable=False, default="GHS")
    paystack_reference = db.Column(db.String(64), unique=True, nullable=False, index=True)
    status = db.Column(db.String(20), nullable=False, default="pending")
    customer_name = db.Column(db.String(120), nullable=False)
    customer_email = db.Column(db.String(120), nullable=False)
    customer_phone = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime)
    delivered_at = db.Column(db.DateTime)  # When order was marked as delivered

    store = db.relationship("Store", backref=db.backref("orders", lazy="dynamic"))
    product = db.relationship("Product", backref=db.backref("orders", lazy="dynamic"))
    user = db.relationship("User", backref=db.backref("orders", lazy="dynamic"))


class Withdrawal(db.Model):
    __tablename__ = "withdrawals"
    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey("stores.id"), nullable=False, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    account_details = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Withdrawal store_id={self.store_id} amount={self.amount}>"
