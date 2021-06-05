from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUserForm, LoginUserForm, CommentForm
from functools import wraps
from flask_gravatar import Gravatar
import os



app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['CKEDITOR_PKG_TYPE'] = 'full'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return RegisterUser.query.get(int(user_id))

#Gravatar Image
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONFIGURE TABLES

class RegisterUser(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    #relationship call
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("CommentsDB", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # relationship call
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("RegisterUser", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # relationship with comments (one blog to many comments)
    comments = relationship("CommentsDB", back_populates="parent_post")


class CommentsDB(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("RegisterUser", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")





db.create_all()


# Pages Route

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterUserForm()
    if form.validate_on_submit():
        email = form.email.data
        if RegisterUser.query.filter_by(email=email).first():
            flash("Email already registered. Please login instead")
            return redirect(url_for('login'))

        password = generate_password_hash(form.password.data,
                                          method='pbkdf2:sha256',
                                          salt_length=8)
        name = form.name.data

        # Registration
        user = RegisterUser(email=email,
                            password=password,
                            name=name)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated, user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUserForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        if RegisterUser.query.filter_by(email=email).first():
            user = RegisterUser.query.filter_by(email=email).first()
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password is wrong")
                return redirect(url_for('login'))
        else:
            flash("Email does not exist in database")
            return redirect(url_for('register'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated, user=current_user)


@app.route("/post/<int:post_id>",methods=["GET","POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    requested_comments = CommentsDB.query.filter_by(post_id=post_id).all()
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("you need to login to comment")
            return redirect(url_for('login'))

        new_comment_entry = CommentsDB(body=comment_form.body.data,
                                       comment_author=current_user,
                                       parent_post=requested_post
                                       )
        db.session.add(new_comment_entry)
        db.session.commit()
        return redirect(url_for('show_post',post_id=post_id))
    return render_template("post.html", post=requested_post,comments=requested_comments, logged_in=current_user.is_authenticated,
                           user=current_user, comment_form = comment_form, post_id=post_id)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated, user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated, user=current_user)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    form = CreatePostForm()
    print(current_user)
    if form.validate_on_submit():

        new_post = BlogPost(author=current_user,
                            title=form.title.data,
                            subtitle=form.subtitle.data,
                            date=date.today().strftime("%B %d, %Y"),
                            body=form.body.data,
                            img_url=form.img_url.data)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated, user=current_user, is_edit = False)


@app.route("/edit-post/<int:post_id>",methods=["GET","POST"])
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated, user=current_user, is_edit = True, post_id=post_id)


def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.email != "shounak.python@gmail.com":
            return abort(403)
        return func(*args, **kwargs)
    return wrapper



@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete/comment/<int:index>")
@admin_only
def delete_comment(index):
    comment_to_delete = CommentsDB.query.get(index)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=comment_to_delete.post_id))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
