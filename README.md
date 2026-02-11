# Shop With Link

Create your store and share one link. Sign up, verify your email, create a store, get a shareable link, and manage products easily. Built for **Ghana** with **Paystack** (GHS) payments. Blue & white UI, user accounts, profile, password change, and orders.

## Setup

```bash
cd shopwithlink
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Copy the example env file and edit it with your values (Paystack from [paystack.com](https://paystack.com), SendGrid from [sendgrid.com](https://sendgrid.com)):

```bash
cp .env.example .env
# Edit .env: set SECRET_KEY, PAYSTACK_*, SENDGRID_API_KEY, SENDGRID_FROM_EMAIL, etc.
```

```bash
python app.py
```

Open http://127.0.0.1:5000

## Features

- **User Flow** — Sign up → Verify email → Create store → Get shareable link → Manage products
- **Auth** — Register (email + password), log in, profile page, change password.
- **Email Verification** — After signup, a 6-digit one-time code is sent via **SendGrid**. Users must verify before using the app; code expires in 10 minutes. Resend is rate-limited (1 per minute).
- **Stores** — Create a store with name and description. Get a unique, shareable link (e.g., `/store/my-store-name`).
- **Products** — Add products (name, description, price, image URL). Edit and delete products easily from the store management page.
- **Public Storefront** — Share your store link with customers. They can view products and click "Buy now" to purchase.
- **Paystack Payments** — Checkout collects name, email, phone; redirects to Paystack to pay; on success, order is saved.
- **Orders** — View your orders with product, store, amount, and date.

## Project layout

- `app.py` — Routes, auth, profile, checkout, Paystack init/verify, orders
- `models.py` — User, Store, Product, Order
- `config.py` — Database, secret key, Paystack keys (from env)
- `templates/` — Landing page, profile, change password, checkout, orders, auth, store/product pages
- `static/style.css` — Blue & white professional styling
- Database: SQLite at `instance/shopwithlink.db`

## Payment not working?

- **Ghana (GHS)**: Currency is Ghanaian Cedi (₵). Paystack requires at least ₵0.10 per transaction. Use test keys (`sk_test_...`, `pk_test_...`) from [Paystack Dashboard](https://dashboard.paystack.com) (Ghana).
- **Callback URL**: After payment, Paystack redirects the customer to your app. On localhost this usually works; if the redirect fails or order stays "pending", run your app behind a public URL (e.g. [ngrok](https://ngrok.com)) and set that as your app's base URL so the callback URL is reachable.
- **Errors**: If "Pay with Paystack" fails, the message shown is the one returned by Paystack (e.g. invalid key, invalid callback). Check the terminal/console for `Paystack initialize failed` logs.
