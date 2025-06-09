from flask import Flask, redirect, render_template, flash, abort, request, url_for
from flask_bootstrap import Bootstrap
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = "SOME SECERT KEY"
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    subscription = db.Column(db.String(100))
    org = db.Column(db.String(100))
db.create_all()

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/science_exp')
def science_exp():
    return render_template("product2.html")

@app.route('/chemistry_exp')
def chemistry_exp():
    return render_template("product3.html")

@app.route('/info_exp')
def info_exp():
    return render_template("product4.html")

@app.route('/code')
def code():
    return render_template("code.html")

@app.route('/DNA')
def DNA_exp():
    return render_template("DNA.html")

@app.route('/agarose_gel_electrophoresis')
def DNA_exp2():
    return render_template("agarose_gel_electrophoresis.html")

@app.route('/chemical_reaction_rate')
def chemistry():
    return render_template("chemical_reaction_rate.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("username")
        password = request.form.get("password")

        if User.query.filter_by(email=email).first():
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=email,
            name=username,
            password=hash_and_salted_password,
            subscription="no subscription",
            org=""
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("index"))

    return render_template("register.html", current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('index'))
    return render_template("login.html", current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/pricing')
def pricing():
    subscription = 'no subscription'
    try:
        user = User.query.get(current_user.id)
        subscription = user.subscription
    except:
        # do nothing
        pass

    return render_template("pricing.html", subscription=subscription)

@app.route('/process_payment/<subscription>')
def process_payment(subscription):
    # go to pay page from eg: chargily
    # let assume that the payment process is successfull

    try:
        user = User.query.get(current_user.id)
        user.subscription = subscription
        db.session.commit()
    except:
        return redirect(url_for("login"))
    return redirect(url_for("index"))


@app.route('/about')
def about_us():
    return render_template("about-us.html")


@app.route('/product')
def product():
    return render_template("product.html")

@app.route('/product1')
def product1():
    return render_template('product1.html')


@app.route('/manage', methods=["GET", "POST"])
def manage():
    if request.method == "POST":
        email = request.form.get("email")
        username = request.form.get("name")
        password = request.form.get("password")
        if current_user.subscription == 'مؤسسة':
            role = request.form.get("role")

        if User.query.filter_by(email=email).first():
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('manage'))

        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        if current_user.subscription == "أستاذ":
            new_user = User(
                email=email,
                name=username,
                password=hash_and_salted_password,
                subscription="طالب",
                org=current_user.id
            )
        else:
            new_user = User(
                email=email,
                name=username,
                password=hash_and_salted_password,
                subscription=role,
                org=current_user.id
            )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("manage"))
    
    user = User.query.get(current_user.id)
    subscription = user.subscription
    if subscription == "طالب": 
        return render_template("index.html")
    else:
        users = User.query.filter_by(org=current_user.id).all()
        if subscription == 'مؤسسة':
            # Separate them by subscription
            teachers = [user for user in users if user.subscription == 'أستاذ']
            students = [user for user in users if user.subscription == 'طالب']
            return render_template("manage.html", subscription=subscription, teachers=teachers, students=students)
        else:
            students = [user for user in users if user.subscription == 'طالب']
            return render_template("manage.html", subscription=subscription, teachers=[], students=students)


if __name__ == "__main__":
    app.run(debug=True)
    