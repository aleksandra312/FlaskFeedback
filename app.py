from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User
from forms import UserForm, LoginForm
from sqlalchemy.exc import IntegrityError


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///user_feedback"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)
db.create_all()

toolbar = DebugToolbarExtension(app)


@app.route('/')
def home_page():
    """Redirect to /register"""
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    """Add a new user. Redirect to /users/<username>"""
    form = UserForm()
    if form.validate_on_submit():
        new_user = returnRegisteredUser(form)
        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken.  Please pick another')
            return render_template('register.html', form=form)

        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect(f"/users/{new_user.username}")

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_user():
    """Log in existing user. Redirect to /users/<username>"""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['username'] = user.username
            return redirect(f"/users/{username}")
        else:
            form.username.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)


@app.route('/users/<username>')
def show_user(username):
    """Return information about a user."""
    if 'username' not in session:
        flash('Please login to see this page.', 'danger')
        return redirect('/login')
    user = User.query.get_or_404(username) 
    return render_template('user.html', user=user)


@app.route('/logout')
def logout_user():
    """Clear any information from the session and redirect to /"""
    session.pop('username')
    flash('Goodbye!', 'info')
    return redirect('/')


@app.route("/users/<username>/delete")
def delete_user(username):
    """Delete the user."""
    if "username" not in session or username != session['username']:
        raise Unauthorized()

    user = User.query.get_or_404(username)
    db.session.delete(user)
    db.session.commit()
    session.pop("username")
    return redirect("/")    


###___Feedback code___###

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """Add new user feedback. Redirect to /users/<username>"""
    if "username" not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        new_feedback = Feedback(
            title=title, 
            content=content, 
            username=username)

        db.session.add(new_feedback)
        db.session.commit()
        flash('New feedback added!', 'success')
        return redirect(f"/users/{username}")

    return render_template("feedback.html", form=form)


@app.route('/users/<int:feedback_id>/feedback/update', methods=['GET', 'POST'])
def edit_feedback(feedback_id):
    """Update user feedback. Redirect to /users/<username>"""
    if "username" not in session:
        flash("Please login first!", "danger")
        return redirect('/login')

    form = FeedbackForm()
    if form.validate_on_submit():
        feedback = Feedback.query.get(feedback_id)
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash('Feedback successfully updated!', 'success')

        return redirect(f"/users/{feedback.username}")

    return render_template("feedback.html", form=form)


@app.route('/users/<int:feedback_id>/feedback/delete', methods=["POST"])
def delete_feedback(feedback_id):
    """Delete feedback"""

    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')

    feedback = Feedback.query.get_or_404(id)

    if feedback.username == session['username']:
        db.session.delete(feedback)
        db.session.commit()
        flash("Feedback deleted!", "info")
        return redirect(f"/users/{feedback.username}")

    flash("You don't have permission to do that!", "danger")
    return redirect(f"/users/{feedback.username}")


def returnRegisteredUser(form):
    """Retrieves user details from Registration form and regiisters a new user."""
    username = form.username.data
    password = form.password.data
    email = form.email.data
    first_name = form.first_name.data
    last_name = form.last_name.data
    return User.register(username, password, email, first_name, last_name)


