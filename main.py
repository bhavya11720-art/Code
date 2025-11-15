from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import email_validator
import pickle
import numpy as np
import pandas as pd



app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------- Models --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- Forms --------------------
class RegisterForm(FlaskForm):
    name = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(r'^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$', message='Must include 1 uppercase letter, 1 digit, and 1 special character.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')



# Load model and feature names
with open("Models/rainfall_prediction_model.pkl", "rb") as rf_model:
    model_data = pickle.load(rf_model)  # Load dictionary
    model = model_data["model"]  # Extract model
    feature_names = model_data["feature_names"]  # Extract feature names

@app.route("/a",methods=['GET'])
def home():
    return render_template("index.html")

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.username == form.name.data) | (User.email == form.email.data)
        ).first()
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



@app.route("/about")
def ome():
    return render_template("about.html")

@app.route("/projects")
def omme():
    return render_template("projects.html")


@app.route("/contact/")
def me():
    return render_template("contact.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Extract data from form using feature names
        input_data = [float(request.form.get(col)) for col in feature_names]

        # Convert to DataFrame with correct column names
        input_df = pd.DataFrame([input_data], columns=feature_names)

        # Make prediction
        prediction = model.predict(input_df)[0]

        return render_template("projects.html", prediction=round(prediction, 2))
    
    except ValueError:
        return render_template("projects.html", error="Invalid input. Please enter valid numerical values.")
    except Exception as e:
        return render_template("projects.html", error=f"An error occurred: {str(e)}")

@app.route("/api/predict", methods=["POST"])
def api_predict():
    try:
        data = request.get_json()

        # Ensure the JSON contains all required features
        input_df = pd.DataFrame([data], columns=feature_names)

        # Make prediction
        prediction = model.predict(input_df)[0]
        
        return jsonify({"prediction": round(prediction, 2)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

