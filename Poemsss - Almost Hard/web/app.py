import os
import string
from time import time, sleep

from flask import Flask, render_template, flash, request, redirect, url_for, Response, make_response
from flask_login import login_user, UserMixin, login_required, logout_user, current_user, login_manager, LoginManager
from flask_sqlalchemy import SQLAlchemy
from redis import Redis
from rq import Queue
from wtforms import StringField, validators
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect

from visitor import visit_user_page

db = SQLAlchemy()
app = Flask(__name__)
app.secret_key = os.urandom(16)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("SQLALCHEMY_DATABASE_URI")
db.init_app(app)
CSRFProtect(app)
my_login_manager = LoginManager()
my_login_manager.init_app(app)
chars = string.ascii_letters
admin_password = ''.join(chars[os.urandom(1)[0] % len(chars)] for i in range(16))
flag = os.environ.get("CHALLENGE_FLAG") or "flag{default}"

q = Queue(connection=Redis(host="redis"))
last_visit = {}
VISIT_COOLDOWN = 20


class User(db.Model):
    username = db.Column(db.String(32), primary_key=True)
    is_active = db.Column(db.Boolean, default=True)
    password = db.Column(db.String(32))
    aboutme = db.Column(db.String(256))
    poem = db.Column(db.Text)


class UserSession(UserMixin):
    def __init__(self, user):
        self.user = user

    def get_id(self):
        return self.user.username

    def is_active(self):
        return self.user.is_active


@app.login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, user_id)
    return UserSession(user) if user else None


class LoginForm(FlaskForm):
    username = StringField(validators=[validators.Length(min=2, max=64)])
    password = StringField(validators=[validators.Length(min=2, max=64)])


class RegisterForm(LoginForm):
    aboutme = StringField(validators=[validators.Length(min=2, max=256)])


class PoemUpdate(FlaskForm):
    poem = StringField(validators=[validators.Length(min=2, max=65536)])
    aboutme = StringField(validators=[validators.Length(min=2, max=256)])


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/healthcheck')
def healthcheck():
    return render_template('index.html')


@app.route('/login', methods=['POST'])
def doLogin():
    previous_url = request.args.get('next')

    if current_user.is_authenticated:
        return redirect(previous_url or url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.get(User, form.username.data)
        if user and user.password == form.password.data:
            login_user(UserSession(user))
            flash('Logged in successfully.', 'success')
            return redirect(previous_url or url_for('index'))
        else:
            flash('Wrong username or password', 'warning')
            return render_template('login.html')
    else:
        flash(f'Invalid log in: {form.errors}', 'error')
        return render_template('login.html')


@app.route('/login', methods=['GET'])
def login():
    previous_url = request.args.get('next')
    if current_user.is_authenticated:
        return redirect(previous_url or url_for('index'))
    return render_template('login.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET'])
def register():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def doRegister():
    form = RegisterForm()
    if form.validate_on_submit():
        existing = db.session.get(User, form.username.data)
        if existing:
            flash(f'User {form.username.data} already exists', 'danger')
            return redirect(url_for('register'))
        else:
            db.session.add(User(username=form.username.data, password=form.password.data, aboutme=form.aboutme.data, poem=""))
            db.session.commit()
            flash('Signed up successfully, redirecting to log in page', 'success')
            return redirect(url_for('login'))
    else:
        flash(f'Invalid sign up data: {form.errors}', 'danger')
        return redirect(url_for('register'))


@app.route('/visit/', methods=['POST'])
@login_required
def doVisit():
    ip = request.remote_addr
    last_timestamp = last_visit.get(ip)
    current_timestamp = time()
    if last_timestamp and (current_timestamp - last_timestamp < VISIT_COOLDOWN):
        flash(f"Current user recently asked for a visit, please wait at least {VISIT_COOLDOWN} seconds between visits", 'warning')
        app.logger.info(f"Rejected enqueue {ip}, current: {current_timestamp}, last {last_timestamp}")
    else:
        last_visit[ip] = current_timestamp
        visit_url = f"http://172.20.0.1:8083/poem/?username={current_user.get_id()}"
        q.enqueue(visit_user_page, visit_url, admin_password)
        flash("Enqueued successfully, an admin will review your poem soon", 'success')
        app.logger.info(f"Enqueued visit from {ip} to {visit_url}, admin pw: {admin_password}")

    return redirect(url_for('poem'))


@app.route('/poem/', methods=['GET'])
@login_required
def poem():
    username = request.args.get("username")
    raw = request.args.get("raw")
    if username and current_user.get_id() == "admin":
        # Admin can visit all users
        target_user = db.session.get(User, username)
        if target_user:
            return renderpoem(raw, target_user)
        else:
            flash(f"User {username} not found", 'danger')
    elif username and not raw:
        flash("Only the admin can visit other users", 'danger')

    return renderpoem(raw, current_user.user)


def renderpoem(raw, user):
    if raw:
        return Response(user.poem, mimetype=request.accept_mimetypes[0][0])
    else:
        return render_template("poem.html", user=user)


@app.route('/poem/', methods=['POST'])
@login_required
def updatePoem():
    form = PoemUpdate()
    if form.validate_on_submit():
        user = db.session.get(User, current_user.get_id())
        user.poem = form.poem.data
        user.aboutme = form.aboutme.data
        db.session.commit()
        flash('Poem updated successfully', 'success')
    else:
        flash(f'Invalid poem update: {form.errors}', 'danger')

    return redirect(url_for('poem'))


@app.login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login?next=' + request.path)



with app.app_context():
    print("Waiting 10 seconds before initializing DB...")
    sleep(10)
    db.create_all()
    print("DB initialized")
    if not db.session.get(User, "admin"):
        db.session.add(User(username="admin", password=admin_password, aboutme=flag, poem="""
        Con diez cañones por banda,
        viento en popa, a toda vela,
        no corta el mar, sino vuela
        un velero bergantín.
        Bajel pirata que llaman,
        por su bravura, El Temido,
        en todo mar conocido
        del uno al otro confín."""
                            ))
        db.session.commit()
    print(f"Admin user password: {admin_password}")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
