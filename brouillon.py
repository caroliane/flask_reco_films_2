from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import mysql.connector
from dotenv import load_dotenv
import os  # Ajoutez cette ligne

app = Flask(__name__)
load_dotenv()
PASSWORD = os.environ['PASSWORD']

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://root:{PASSWORD}@localhost/reco_films'  # Remplacez 'votre_mot_de_passe_mysql' par votre mot de passe MySQL
app.config['SECRET_KEY'] = 'thisisasecretkey'

db = SQLAlchemy()
bcrypt = Bcrypt(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)  # Augmentez la longueur à 255


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField('Email', validators=[
                        InputRequired(), Length(max=255)], render_kw={"placeholder": "E-mail"})
    password = PasswordField('Password', validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = Users.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')

    def validate_email(self, email):
        existing_user_email = Users.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError(
                'An account with that email already exists. Please use a different email.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
                        InputRequired(), Length(max=255)], render_kw={"placeholder": "E-mail"})
    password = PasswordField('Password', validators=[
                        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f'Welcome {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = Users(username=form.username.data,
                         email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True, port=5003)
