from flask import Blueprint, render_template,request,flash, redirect, url_for
from . import db
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import  login_user,login_required,current_user,logout_user


auth = Blueprint('auth',__name__)

@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email = email).first()
        if user:
            if check_password_hash(user.Password, password):
                flash('Loggedin successfully', category='success')
                login_user(user, remember=True)
                return(redirect(url_for('views.home')))
            else:
                flash('email or password doesnot match, try again',category='error')
        else:
            flash('Email doesnot exist',category='error')
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

@auth.route("/signup",methods=['GET','POST'])
def signup():
    if request.method == "POST":
        email = request.form.get('email')
        name = request.form.get('name')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.',category='error')
        elif len(name)<2:
            flash("Name must be more than 2.",category='error')
        elif(len(email)<1):
            flash("please enter email.", category='error')
        elif(len(password1)<1):
            flash("Please enter password.", category='error')
        elif(password1!=password2):
            flash("Password doesnt match.", category='error')
        else:
            new_user = User(name=name,email=email, Password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account Created", category='Success')

    return render_template("signup.html", user=current_user)