from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps
import os
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

ckeditor = CKEditor(app)
Bootstrap(app)

# Configure the login manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

# Create a table for User
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    blog_posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


# Create a table for BlogPost
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("User", back_populates="blog_posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="blog_post")


# Create a table for Comments
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("User", back_populates="comments")
    blog_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    blog_post = relationship("BlogPost", back_populates="comments")


# Only required once, when creating DB.
db.create_all()
db.session.commit()


# Create a decorator function called "admin_only" that only allows the user with the id being 1 to access the page.
def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        print("decorator called")
        if current_user.is_authenticated:
            if current_user.id != 1:
                flash("You do not have permission to access this page.")
                return redirect(url_for('login')), 403
            else:
                return f(*args, **kwargs)
        else:
            flash("You do not have permission to access this page.")
            return redirect(url_for('login')), 403

    return wrapper


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    already_exists = User.query.filter_by(email=form.email.data).first()
    if already_exists:
        flash("You have already signed up with that email address. Please login instead.")
        return redirect(url_for("login"))

    if form.validate_on_submit():
        hashed_and_salted_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
        new_user = User(email=form.email.data, password=hashed_and_salted_password, name=form.name.data.title())
        try:
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:
            return e
        else:
            print(f"User {new_user.email} created")
            login_user(new_user)
            flash("You have successfully registered and logged in.")
            return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("You have successfully logged in.")
                return redirect(url_for("get_all_posts"))
            else:
                flash("Incorrect password.")
                return redirect(url_for("login"))
        else:
            flash("Incorrect email.")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    # Add the comment to the database if the form is valid and the user is logged in.
    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment_to_add = Comment(text=form.body.data, author=current_user, blog_post=requested_post)
            db.session.add(comment_to_add)
            db.session.commit()
            return redirect(url_for("show_post", post_id=post_id))

        else:
            flash("You must be logged in to comment.")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    app.run()
