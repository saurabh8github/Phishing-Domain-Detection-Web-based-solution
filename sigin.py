from flask import Flask, render_template, url_for, request, session, redirect, flash
from flask_pymongo import PyMongo
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'testing'

app.config['MONGO_dbname'] = 'userdata'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/userdata'

mongo = PyMongo(app)

@app.route("/")
@app.route("/main")
def main():
    return render_template('index.html')


# @app.route("/signup", methods=['POST', 'GET'])
# def signup():
#     if request.method == 'POST':
#         users = mongo.db.userdata
#         signup_user = users.find_one({'username': request.form['username']})

#         if signup:
#             flash(request.form['username'] + ' username is already exist')
#             hashed = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt(14))
#             users.insert({'username': request.form['username'], 'password': hashed, 'email': request.form['email']})
#         return redirect(url_for('signin'))

#     return render_template('signup.html')
@app.route("/signup", methods=['POST', 'GET'])
def signups():
    if request.method == 'POST':
        users = mongo.db.users
        # Check if a user with the same username already exists
        existing_user = users.find_one({'username': request.form['username']})

        if existing_user:
            flash(request.form['username'] + ' username is already taken')
            return redirect(url_for('/signup'))

        # If the username is not taken, proceed with user registration
        hashed = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt(14))
        users.insert_one({'username': request.form['username'], 'password': hashed, 'email': request.form['email']})
        flash('Registration successful! Please log in.')
        return redirect(url_for('/signin'))

    return render_template('signup.html')


@app.route('/index')
def index():
    if 'username' in session:
        return render_template('index.html', username=session['username'])

    return render_template('index.html')

@app.route('/signins', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        users = mongo.db.users
        signin_user = users.find_one({'username': request.form['username']})

        if signin_user:
            if bcrypt.checkpw(request.form['password'].encode('utf-8'), signin_user['password']):

                session['username'] = request.form['username']
                return redirect(url_for('index'))

        flash('Username and password combination is wrong')
        return render_template('templates/signin.html')

    return render_template('signin.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
    app.run()
