from flask import Flask, render_template, request, redirect, url_for, session, flash, Blueprint
import pyodbc 
import webbrowser
import datetime
import threading
from algosdk.v2client import algod
from algosdk import mnemonic
from algosdk import transaction
from flask import Flask, request, url_for
from flask_mail import Mail, Message
import os
from itsdangerous import URLSafeSerializer, SignatureExpired, URLSafeTimedSerializer
import string
from flask_recaptcha import ReCaptcha
import re
import socket
from flask_login import LoginManager, login_user, logout_user, current_user


#from flaskblog import User, Post


# Algod API key
algod_token = 'FXzuAqrOV71I7QBnq8M009ACS6UUqvW11RBiPIj9'
algod_address ='https://testnet-algorand.api.purestake.io/ps2'

app = Flask(__name__)

# Google captcha details
app.config['RECAPTCHA_SITE_KEY'] = '6LfMGR8cAAAAAPfUCqHaAgxBwIRHa_eZALmeX2Ak'
app.config['RECAPTCHA_SECRET_KEY'] = '6LfMGR8cAAAAAO8-saQCyj9J_Z-dtxZSMS10RgS5'
recaptcha = ReCaptcha(app=app)

# Google email authorization
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'rakeshvwlts@gmail.com'
app.config['MAIL_PASSWORD'] = 'V@95Rakesh$'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)


app.secret_key = 'password'

# Generating token for reset password and verification email
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

#SQL Server DB connection
conn = pyodbc.connect(r'DRIVER={SQL Server};'
    r'SERVER=WL21L-02;'
    r'DATABASE=Sample;'
    r'Trusted_Connection=yes;')

port = 5001
url = "http://127.0.0.1:{0}".format(port)
threading.Timer(1.25, lambda: webbrowser.open(url)).start()


#Default page
@app.route('/')
def index():
  # check if the users exist or not
    session['attempt'] = 5
    if not session.get("username"):
        # if not there in the session then redirect to the login page
        return redirect("/login")
    return redirect('/pricing') 

# Logout condition
@app.route("/logout")
def logout():
    logout_time = datetime.datetime.now()
    cursor = conn.cursor()
    cursor.execute("update login_details set logouttime=? where logintime in (select top 1 logintime from login_details where username = ? order by LoginID desc)" , logout_time,session["username"])
    conn.commit()
    session["username"] = None
    flash("You have been logged out!")
    return redirect("/")


#Registration page
@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'mnemonic' in request.form and 'email' in request.form :
        username = request.form['username']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        mnemonic_key = request.form['mnemonic']
        country = request.form['country']
        ip_address=socket.gethostbyname(socket.gethostname())
        mnemonic_phrase = mnemonic_key
        #Checking the length of mnemonic phrase
        length_of_mnemonic = sum([i.strip(string.punctuation).isalpha() for i in mnemonic_phrase.split()])
        created_date = datetime.datetime.now()
        email = request.form['email']

        ## To check user already exists ##
        cursor = conn.cursor()
        cursor.execute("exec verifying_user_name @username = ?",username) #username validation
        account = cursor.fetchone()
        cursor.execute("select * from registration_details where email = ?",email) #email validation
        checkemailexists = cursor.fetchone()
        cursor.execute("select * from registration_details where mnemonic_key = ?",mnemonic_phrase) #mnemonic validation
        checkmnemonicexists = cursor.fetchone()

        if account:
            msg = 'Account already exists !'
            return render_template('contact.html', msg = msg, port=port)
        elif checkemailexists:
            msg = 'Email already exists !'
            return render_template('contact.html', msg = msg, port=port)
        elif checkmnemonicexists:
            msg = 'Mnemonic already exists !'
            return render_template('contact.html', msg = msg, port=port)
        elif len(new_password) < 8:
            msg="Make sure your password is at lest 8 letters"
            return render_template('contact.html', msg = msg, port=port)
        elif re.search(r"[a-z]", new_password) is None:
            msg="Make sure your password has one lowercase letter in it"
            return render_template('contact.html', msg = msg, port=port)
        elif re.search(r"[A-Z]", new_password) is None:
            msg="Make sure your password has one capital letter in it"
            return render_template('contact.html', msg = msg, port=port)
        elif re.search(r"[0-9]", new_password) is None:
            msg="Make sure your password has one number in it"
            return render_template('contact.html', msg = msg, port=port)     
        elif length_of_mnemonic < 25:
            msg = 'Mnemonic length mismatch'
            return render_template('contact.html', msg = msg, port=port)
        elif new_password != confirm_password:
            msg = 'Password mismatch'
            return render_template('contact.html', msg = msg, port=port)
        else:
            private_key = mnemonic.to_private_key(mnemonic_phrase)
            public_key = mnemonic.to_public_key(mnemonic_phrase)
            token = s.dumps(email, salt='email_confirm')
            print("insert records in DB")
            #cursor.execute('INSERT INTO registration_details(username,mnemonic_key,email,private_key,public_key, created_date, new_password, confirm_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', username, mnemonic_key, email, private_key, public_key,created_date, new_password, confirm_password)
            cursor.execute('exec insert_registration_details @username=?, @email= ?, @mnemonic_key = ?, @public_key = ?, @private_key=?,@created_date=?,@new_password=?,@confirm_password=?, @confirmed=0, @ip_address=?, @country=?, @attempt_block = 0;', username, email, mnemonic_key, public_key, private_key, created_date, new_password, confirm_password, ip_address, country)
            conn.commit()
            print(username)
            send_message(request.form) #Reqesting form to send verification email
            return redirect(url_for('verify_email'))
        
    return render_template('contact.html', msg = msg, port=port)

@app.route('/login', methods =['GET', 'POST'])
def login():

    msg = ''
    message = ''
    duration = 86400
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password']
        ip_address=socket.gethostbyname(socket.gethostname())
        login_time = datetime.datetime.now()
        cursor = conn.cursor()
        cursor.execute("exec verifying_user_password @username = ?, @password = ?;",username, password)
        account = cursor.fetchone()
        try:
            cursor.execute("select top 1 logintime from registration_details a join login_details b on a.username=b.username where b.username = ? order by loginid desc",username)
            last_login_time = cursor.fetchone()
            duration = login_time - last_login_time[0]
            duration = duration.total_seconds()
        except TypeError:
            print('No duration')


        print(duration)
        message = '' # Create empty message
        try:            
            if account[3]==1 and account[4]==0:
                session['loggedin'] = True
                session['username'] = account[0]
                session['password'] = account[1]
                session['public_key'] = account[2]
                msg = 'Logged in successfully !'
                cursor.execute("insert into login_details (username,ip_address,logintime,status) values (?,?,?,1)",username,ip_address,login_time)
                conn.commit()
                return redirect('/pricing')
            elif account[3]==0 and account[4]==0:
                return render_template('verification_message.html')
            elif account[4]==1 and duration >= 86400:
                cursor.execute("update registration_details set attempt_block=0 where username = ?",username)
                conn.commit()
                cursor.execute("insert into login_details (username,ip_address,logintime,status) values (?,?,?,0)",username,ip_address,login_time)
                conn.commit()
                return redirect('/pricing')
            elif account[4]==1 and duration < 86400:
                msg = 'Your account is blocked for 24hr, due to multiple login attempts. Try after some time'
                cursor.execute("insert into login_details (username,ip_address,logintime,status) values (?,?,?,0)",username,ip_address,login_time)
                conn.commit()
            elif recaptcha.verify(): # Use verify() method to see if ReCaptcha is filled out
                message = 'Thanks for filling out the form!' # Send success message
            else:
                message = 'Please fill out the ReCaptcha!' # Send error message
        except TypeError:
            msg = 'Incorrect username / password !'
            cursor.execute("insert into login_details (username,ip_address,logintime,status) values (?,?,?,0)",username,ip_address,login_time)
            conn.commit()
    attempt= session.get('attempt')
    attempt -= 1
    session['attempt']=attempt
    #print(attempt,flush=True)
    if attempt==1:
        client_ip= session.get('client_ip')
        cursor.execute("update registration_details set attempt_block=1 where username = ?;",username)
        conn.commit()
        flash('This is your last attempt, Your account will be blocked for 24hr, Attempt %d of 5'  % (client_ip,attempt), 'error')
        cursor.execute("insert into login_details (username,ip_address,logintime,status) values (?,?,?,0)",username,ip_address,login_time)
        conn.commit()
    elif attempt==3:
        flash('Invalid login credentials, Attempts %d of 5'  % attempt, 'error')
        cursor.execute("insert into login_details (username,ip_address,logintime,status) values (?,?,?,0)",username,ip_address,login_time)
        conn.commit()
    elif attempt==2:
        flash('Invalid login credentials, Attempts %d of 5'  % attempt, 'error')
        cursor.execute("insert into login_details (username,ip_address,logintime,status) values (?,?,?,0)",username,ip_address,login_time)
        conn.commit()
    return render_template('login.html', msg = msg, message=message)


@app.route('/pricing', methods =['GET', 'POST'])
def pricing():
    return render_template('pricing.html',username=session.get("username"), public_key=session.get('public_key'))

# Sending verification email for registration
def send_message(message):
    print(message.get('username'))

    msg = Message(sender = 'rakeshvwlts@gmail.com',
            recipients = [message.get('email')], subject='Verify Your Account'
    )
    email=message.get('email')
    token = s.dumps(email, salt='email_confirm')
    confirm_url = url_for(
            'confirm_email',
            token=token,
            _external=True)
    print(confirm_url)
    msg.html = render_template('verify_email.html', username=message.get('username'), token=token, confirm_url=confirm_url)  
    mail.send(msg)

# Confirming user to access the account via email
@app.route('/confirm_email/<token>')
def confirm_email(token):
    print(token)
    try:
        email = s.loads(token, max_age=21600, salt='email_confirm')
    except SignatureExpired: 
        return render_template('token_expired.html', token=token)
    print (email)
    cursor = conn.cursor()
    cursor.execute("select token, confirmed from registration_details where email = ?",email)
    account = cursor.fetchone()
    mesg = 'Your email id verified successfully'
    if account[0]==token and account[1]==1:
        mesg='Your email id is already verified. You can login now'
        return render_template('login.html',mesg=mesg)

    #try:
    #    email = s.loads(token, max_age=20, salt='email_confirm')
    #except SignatureExpired: 
    #    return '<h1> The link is expired. <h1>'
    cursor.execute("update registration_details set token=?, confirmed=1 where email = ?",token,email)
    conn.commit()
    return render_template('login.html',mesg=mesg)

@app.route('/verify_email',  methods =['GET', 'POST'])
def verify_email():
    return render_template('verification_message.html')

@app.route('/verify_reset_email/<token>')
def verify_reset_email(token):
    cursor = conn.cursor()
    email = s.loads(token, max_age=None, salt='email_confirm')
    cursor.execute("select username,email,public_key,token,reset_token from registration_details where email =?",email)
    account = cursor.fetchone()
    cursor.execute("select username,email,public_key,token,reset_token from registration_details where public_key =?",email)
    reset_account = cursor.fetchone()
    # cursor.execute("select username,email,public_key,token,reset_token from registration_details where email =?",email)
    #account = cursor.fetchone()
    try:
        token=account[3]
        msg = Message(sender = 'rakeshvwlts@gmail.com',
                recipients = [account[1]], subject='Verify Your Account'
        )
        token = s.dumps(account[1], salt='email_confirm')
        confirm_url = url_for(
                'confirm_email',
                token=token,
                _external=True)
        print(confirm_url)
        msg.html = render_template('verify_email.html', username=account[0], token=token, confirm_url=confirm_url)  
        mail.send(msg)
        return render_template('verification_message.html')
    except TypeError:
        token==reset_account[4]
        msg = Message(sender = 'rakeshvwlts@gmail.com',
                recipients = [reset_account[1]], subject='Verify Your Account'
        )
        token = s.dumps(reset_account[2], salt='email_confirm')
        confirm_url = url_for(
                'reset_new_password',
                token=token,
                _external=True)
        print(confirm_url)
        msg.html = render_template('reset_email_msg.html', username=reset_account[0], token=token, confirm_url=confirm_url)  
        mail.send(msg)
        return render_template('verification_message.html')


@app.route('/reset_password', methods =['GET', 'POST'])
def reset_password():
    mesg = ''
    if request.method == 'POST' and 'email' in request.form:
        email = request.form['email']
        cursor = conn.cursor()
        cursor.execute("select * from registration_details where email = ?",email)
        checkemailexists = cursor.fetchone()
        token = s.dumps(checkemailexists[4], salt='email_confirm')
        cursor.execute("update registration_details set reset_token = ? where email = ?", token, email)
        conn.commit()
        if checkemailexists:
            mesg = 'A reset password link send to you email id'
            msg = Message(sender = 'rakeshvwlts@gmail.com',
            recipients = [email], subject='Reset Password'
            )

            msg.html = render_template('reset_email_msg.html', username=checkemailexists[2], email=email, token=token)
            mail.send(msg)
        else:
            mesg = 'Given email is not registered' 
    return render_template('reset_password.html', mesg=mesg)

@app.route('/reset_new_password/<token>', methods =['GET', 'POST'])
def reset_new_password(token):
    msg = ''
    if request.method == 'POST' and 'new_password' in request.form and 'confirm_new_password' in request.form:
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']
        try:
            public_key = s.loads(token, max_age=21600, salt='email_confirm')
        except SignatureExpired: 
            return render_template('token_expired.html', token=token)
        if new_password != confirm_new_password:
            msg = 'Password mismatch'
            return render_template('contact.html', msg = msg, port=port)
        else:
            cursor = conn.cursor()
            print(new_password)
            cursor.execute("update registration_details set new_password=?, confirm_password=? where public_key = ?", new_password, confirm_new_password,public_key)
            conn.commit()
            msg='Reset password Successfully'
            return  render_template('login.html', msg=msg)
    return render_template('reset_new_password.html', msg=msg, token=token, port=port)


if __name__ == "__main__":
    app.run(debug=False, port=5001)

