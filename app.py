from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'finance_tracker_secret_2024'

# ── MongoDB Connection ──────────────────────────────────────────────
client = MongoClient('mongodb://localhost:27017/')
db = client['finance_tracker']

users_col    = db['users']
income_col   = db['income']
expense_col  = db['expenses']
budget_col   = db['budgets']


# ── JWT Decorator ───────────────────────────────────────────────────
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token missing!'}), 401
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_col.find_one({'email': data['email']})
        except:
            return jsonify({'message': 'Invalid token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════════
# FORM 1A — SIGN UP
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/signup', methods=['POST'])
def signup():
    data     = request.json
    name     = data.get('name', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    if not all([name, email, password]):
        return jsonify({'message': 'All fields are required!'}), 400

    if users_col.find_one({'email': email}):
        return jsonify({'message': 'Email already registered!'}), 409

    users_col.insert_one({
        'name'      : name,
        'email'     : email,
        'password'  : generate_password_hash(password),
        'created_at': datetime.datetime.utcnow()
    })
    return jsonify({'message': 'Account created successfully!'}), 201


# ══════════════════════════════════════════════════════════════════════
# FORM 1B — LOGIN
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/login', methods=['POST'])
def login():
    data     = request.json
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    if not all([email, password]):
        return jsonify({'message': 'Email and password required!'}), 400

    user = users_col.find_one({'email': email})
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid email or password!'}), 401

    token = jwt.encode({
        'email': email,
        'exp'  : datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        'token'  : token,
        'name'   : user['name'],
        'message': 'Login successful!'
    })


# ══════════════════════════════════════════════════════════════════════
# FORM 2 — ADD INCOME
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/income', methods=['POST'])
@token_required
def add_income(current_user):
    data = request.json

    if not data.get('amount') or not data.get('source'):
        return jsonify({'message': 'Amount and source are required!'}), 400

    income_col.insert_one({
        'user_email' : current_user['email'],
        'source'     : data.get('source'),
        'amount'     : float(data.get('amount')),
        'date'       : data.get('date'),
        'note'       : data.get('note', ''),
        'created_at' : datetime.datetime.utcnow()
    })
    return jsonify({'message': 'Income added successfully!'})


@app.route('/api/income', methods=['GET'])
@token_required
def get_income(current_user):
    records = list(income_col.find(
        {'user_email': current_user['email']},
        {'_id': 0}
    ).sort('created_at', -1))
    return jsonify(records)


# ══════════════════════════════════════════════════════════════════════
# FORM 3 — ADD EXPENSE
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/expense', methods=['POST'])
@token_required
def add_expense(current_user):
    data = request.json

    if not data.get('amount') or not data.get('category'):
        return jsonify({'message': 'Amount and category are required!'}), 400

    expense_col.insert_one({
        'user_email' : current_user['email'],
        'category'   : data.get('category'),
        'amount'     : float(data.get('amount')),
        'date'       : data.get('date'),
        'description': data.get('description', ''),
        'created_at' : datetime.datetime.utcnow()
    })
    return jsonify({'message': 'Expense added successfully!'})


@app.route('/api/expense', methods=['GET'])
@token_required
def get_expenses(current_user):
    records = list(expense_col.find(
        {'user_email': current_user['email']},
        {'_id': 0}
    ).sort('created_at', -1))
    return jsonify(records)


# ══════════════════════════════════════════════════════════════════════
# FORM 4 — SET BUDGET
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/budget', methods=['POST'])
@token_required
def set_budget(current_user):
    data = request.json

    if not data.get('month') or not data.get('total_budget'):
        return jsonify({'message': 'Month and total budget are required!'}), 400

    budget_col.update_one(
        {'user_email': current_user['email'], 'month': data.get('month')},
        {'$set': {
            'user_email'   : current_user['email'],
            'month'        : data.get('month'),
            'total_budget' : float(data.get('total_budget')),
            'food'         : float(data.get('food', 0)),
            'transport'    : float(data.get('transport', 0)),
            'education'    : float(data.get('education', 0)),
            'entertainment': float(data.get('entertainment', 0)),
            'other'        : float(data.get('other', 0)),
            'updated_at'   : datetime.datetime.utcnow()
        }},
        upsert=True
    )
    return jsonify({'message': 'Budget saved successfully!'})


@app.route('/api/budget', methods=['GET'])
@token_required
def get_budget(current_user):
    month = request.args.get('month')
    query = {'user_email': current_user['email']}
    if month:
        query['month'] = month
    budget = budget_col.find_one(query, {'_id': 0}, sort=[('updated_at', -1)])
    if not budget:
        return jsonify({'message': 'No budget found'}), 404
    return jsonify(budget)


# ══════════════════════════════════════════════════════════════════════
# DASHBOARD SUMMARY
# ══════════════════════════════════════════════════════════════════════
@app.route('/api/summary', methods=['GET'])
@token_required
def get_summary(current_user):
    email = current_user['email']

    # Total income
    incomes  = list(income_col.find({'user_email': email}, {'_id': 0}))
    expenses = list(expense_col.find({'user_email': email}, {'_id': 0}))

    total_income  = sum(i['amount'] for i in incomes)
    total_expense = sum(e['amount'] for e in expenses)
    balance       = total_income - total_expense

    # Expense by category
    category_totals = {}
    for e in expenses:
        cat = e.get('category', 'Other')
        category_totals[cat] = category_totals.get(cat, 0) + e['amount']

    return jsonify({
        'total_income' : total_income,
        'total_expense': total_expense,
        'balance'      : balance,
        'by_category'  : category_totals,
        'income_count' : len(incomes),
        'expense_count': len(expenses)
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)