from flask import Flask, render_template, flash, request, url_for, redirect, session,  get_flashed_messages
from flask_mail import Mail, Message
from Forms.forms import RegistrationForm, LoginForm
from passlib.hash import sha256_crypt
from functools import wraps
import random
import gc, os
import ibm_db

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

# Setting up mailing config!
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_TLS=False,
    MAIL_USE_SSL=True,
    MAIL_USERNAME = '<mail username>',
    MAIL_PASSWORD = '<mail paswword>'   #stored as environment variable.
)
mail = Mail(app)
conn=ibm_db.connect('DATABASE=bludb;HOSTNAME=<HOSTNAME>;PORT=<PORT>;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;UID=<UID>;PWD=<PWD>','','')



def admin_access_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session['username'] == 'admin':
            return f(*args, **kwargs)
        else:
            flash("Access Denied, login as admin", "danger")
            return redirect(url_for('login_page'))
    return wrap

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args,**kwargs)
        else:
            flash('You need to login first!', "warning")
            return redirect(url_for('login_page'))
    return wrap

def already_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            flash("You are already logged in!", "success")
            return redirect(url_for('dashboard'))
        else:
            return f(*args, **kwargs)
    return wrap

@app.route('/logout/')
@login_required
def logout():
    flash("You have been logged out!", "success")
    session.clear()
    gc.collect()
    return redirect(url_for('main'))

def verify(_username, _password):
    try:
        print("Database connected")
        username=_username
        password=_password
        sql = 'select * from profiles where username='+'\''+username+'\''
        stmt = ibm_db.exec_immediate(conn, sql)
        dictionary = ibm_db.fetch_assoc(stmt)
        if dictionary != False:
            if sha256_crypt.verify(_password,dictionary["PASSWORD"]):
                return True  
            else:
                flash("Invalid Credentials, password isn't correct!", "danger")
                return False       
        else:
            flash("No such user found with this username", "warning")
            return False
    except:
        print ("Database error",ibm_db.conn_errormsg())
        return False


@app.route('/', methods=['GET','POST'])
def main():
    return render_template('main.html')


@app.route('/dashboard/',methods=['GET','POST'])
@login_required
def dashboard():
    expensedetails = []
    sql = "SELECT AMOUNT,DETAILS,CHAR(DATE(DANDT),USA) AS DATEADDED, CHAR(TIME(DANDT),USA) AS TIMEADDED FROM USERDATA WHERE USERID = ?"
    stmt = ibm_db.prepare(conn, sql)
    print(session["username"])
    ibm_db.bind_param(stmt, 1, session["username"])
    ibm_db.execute(stmt)
    details = ibm_db.fetch_assoc(stmt)
    while details != False:
        expensedetails.append(details)
        details = ibm_db.fetch_assoc(stmt)
    
    label = [row['DATEADDED'] for row in expensedetails]
    
    
    amountlabel = [row['AMOUNT'] for row in expensedetails]
    
    print(request.args.get('success'))

    sql2 = "SELECT SUM(AMOUNT) AS TOTALVAL FROM USERDATA WHERE USERID = ?"
    stmt2 = ibm_db.prepare(conn, sql2)
    ibm_db.bind_param(stmt2, 1, session["username"])
    ibm_db.execute(stmt2)
    totalexpense = ibm_db.fetch_assoc(stmt2)
    if totalexpense['TOTALVAL'] is None:
        totalexpense['TOTALVAL'] = 0


    sql3 = "SELECT SUM(AMOUNT) AS TOTALVAL FROM WALLET WHERE WALLETID = ?"
    stmt3 = ibm_db.prepare(conn, sql3)
    ibm_db.bind_param(stmt3, 1, session["username"])
    ibm_db.execute(stmt3)
    walletbalance = ibm_db.fetch_assoc(stmt3)
    if walletbalance['TOTALVAL'] is None:
        walletbalance['TOTALVAL'] = 0
        availablebalance = 0
    else:
        availablebalance = int(
            walletbalance['TOTALVAL']) - int(totalexpense['TOTALVAL'])
    if (availablebalance <= 50):
        flash("Your balance is too low!!!")
    elif (availablebalance > 50 and availablebalance <= 200):
        flash("Your balance is getting low so take care of your expenses...!!!")
    return render_template('dashboard.html', dashboard='active', name=session["username"], success=request.args.get('success'), danger=request.args.get('danger'), expensedetails=expensedetails, totalexpense=totalexpense['TOTALVAL'], walletbalance=availablebalance,label=label, amountlabel=amountlabel)

@app.route('/addmoney', methods=['POST'])
@login_required
def addmoney():
    try:
        amount = request.form['walletamount']
        print("Balance:")
        print(int(amount))
        if (int(amount) == 0):
            flash("Please enter some amount", "danger")
            return redirect(url_for('dashboard'))

        else:
            sql="select * from wallet where walletid=?"
            stmt = ibm_db.prepare(conn, sql)
            ibm_db.bind_param(stmt, 1, session["username"])
            ibm_db.execute(stmt)
            account = ibm_db.fetch_assoc(stmt)
            print(account)
            if account!=False:
                sql = "update wallet set amount=amount+? where walletid=?"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, int(amount))
                ibm_db.bind_param(stmt, 2, session["username"])
                print("Executing...")
                ibm_db.execute(stmt)
                print("Executed!!")
                flash("Money added successfully","success")
                return redirect(url_for('dashboard'))
            else:
                sql = "INSERT INTO WALLET(WALLETID,AMOUNT) VALUES(?,?)"
                stmt = ibm_db.prepare(conn, sql)
                ibm_db.bind_param(stmt, 1, session["username"])
                ibm_db.bind_param(stmt, 2, int(amount))
                ibm_db.execute(stmt)
                flash("Money added successfully","success")
                return redirect(url_for('dashboard'))
    except Exception as e:
        print(e)
        flash("Unexpexcted error occured")
        return redirect(url_for('dashboard'))



@app.route('/login/', methods=['GET','POST'])
@already_logged_in
def login_page():
    try:
        form = LoginForm(request.form)
        if request.method == 'POST':
            # to create data base first!
            _username = form.username.data
            _password = form.password.data

            # check if username and password are correct
            if verify(_username, _password) is False:
                return render_template('login.html', form=form)
            session['logged_in'] = True
            session['username'] = _username
            
            gc.collect()
            return redirect(url_for('dashboard',success='Login Successfull'))
            
        return render_template('login.html', form=form)
    except Exception as e:
        return render_template('error.html',e=e)

@app.route('/register/', methods=['GET','POST'])
def register_page():
    try:
        form = RegistrationForm(request.form)
        if request.method == 'POST' and form.validate():
            _username = form.username.data
            _name = form.name.data
            _email = form.email.data
            _password = sha256_crypt.encrypt(str(form.password.data))
            sql = 'select * from profiles where username='+'\''+_username+'\''
            stmt = ibm_db.exec_immediate(conn, sql)
            dictionary = ibm_db.fetch_assoc(stmt)
            if dictionary == False:
                try:
                    insertValueQuery='insert into profiles values(?,?,?,?)'
                    print(_username+' '+_name+' '+_password+' '+_email)
                    param=_name,_username,_email,_password
                    stmt = ibm_db.prepare(conn, insertValueQuery)
                    ibm_db.execute(stmt, param)
                    flash("Thank you for registering!", "success")
                    gc.collect()
                    session['logged_in'] = True
                    session['username'] = _username
                    session.modified = True
                    return redirect(url_for('dashboard'))
                except Exception as e:
                    print(e)
                    return render_template('error.html',e=e)      
            else:
                flash('User Already registered with  username {}'.format(_username), "warning")
                return render_template('register.html', form=form)
        return render_template('register.html', form=form)
    except Exception as e:
        return render_template('error.html',e=e)

@app.route('/forget_password/', methods=['GET', 'POST'])
def forget_password():
    _email = None
    try:
        if request.method=="POST":
            if request.form['submit'] == "Send Email":
                #check if email matches in database
                _email = request.form['email']
                sql = 'select * from profiles where email='+'\''+_email+'\''
                stmt = ibm_db.exec_immediate(conn, sql)
                dictionary = ibm_db.fetch_assoc(stmt)
                if dictionary == False:
                    flash('Email is not registered with us', "danger")
                    _email = None
                else:
                    session['username'] = dictionary["USERNAME"]
                    msg = Message('Hello, your personal expense manager app!', sender = '<admin-mail-id>', recipients = [_email])
                    secret_key = random.randint(1000,10000)
                    session['otp'] = secret_key
                    session.modified = True
                    msg.body = "Your One Time password: {}. \n Valid till half an hour from the generation of the OTP.".format(secret_key)
                    mail.send(msg)
                    flash("Mail Sent!", "success")
                return render_template('forget_password.html')
            if request.form['submit'] == "Verify OTP":
                otp = request.form['otp']				
                if 'username' in session:
                    if int(otp) == session['otp']:
                        session['logged_in'] = True
                        return redirect(url_for('dashboard'))
                    else:
                        flash("OTP is incorrect. Try again!", "warning")
                        return render_template('forget_password.html')
                else:
                    flash("First enter email!")
                    return render_template('forget_password.html')
        else:
            return render_template('forget_password.html')
    except Exception as e:
        return render_template('error.html', e=e)

@app.errorhandler(500)
@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', e=e)


if __name__ == "__main__":
    app.run(debug=True)
