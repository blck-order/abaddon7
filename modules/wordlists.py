# modules/wordlists.py

REST_ROUTES = [
    'users', 'auth', 'login', 'payment', 'transaction', 'order', 'checkout',
    'balance', 'refund', 'webhook', 'token', 'verify', 'status', 'charge',
    'api/v1/users', 'api/v1/auth', 'api/v1/payment', 'api/v2/token'
]

API_PARAMS = [
    'id', 'user_id', 'token', 'amount', 'currency', 'email', 'phone',
    'country', 'reference', 'callback_url', 'return_url', 'session_id',
    'payment_method', 'customer_id', 'order_id', 'signature', 'api_key'
]
