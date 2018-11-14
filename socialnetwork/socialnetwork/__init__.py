#!/usr/bin/python
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, render_template, request, Blueprint, redirect, url_for, session, flash, current_app
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from PIL import Image
from sqlalchemy import func
from flask_login import login_required
from wtforms import TextAreaField
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer.backend.sqla import SQLAlchemyBackend
from flask_login import current_user, login_user, logout_user
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from wtforms import ValidationError
from flask_wtf.file import FileField, FileAllowed
from flask_dance.consumer.backend.sqla import OAuthConsumerMixin
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os


app = Flask(__name__)
app.config.update(
    SECRET_KEY="hcculdcpxaauasotixrjdvjpre",
    ENV='Production',
    SQLALCHEMY_DATABASE_URI='sqlite:///socialnetworkdb.sqlite',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    GOOGLE_OAUTH_CLIENT_ID='119051372590-r419hgkam5hcg7mbf2lv6i1hi4t7ct3n.apps.googleusercontent.com',
    GOOGLE_OAUTH_CLIENT_SECRET='fyGxtAaGrMcHo6Yjg-StvoLu',
    GOOGLE_OAUTH_CLIENT_SCOPE=[
        "https://www.googleapis.com/auth/plus.me",
        "https://www.googleapis.com/auth/userinfo.email",
    ],
    GOOGLE_OAUTH_CLIENT_USERINFO_URI="/oauth2/v2/userinfo"
)
db = SQLAlchemy(app)

# Environment Configuration
APP_ROOT = os.path.join(os.path.dirname(__file__), '..')
dotenv_path = os.path.join(APP_ROOT, '.env')
load_dotenv(dotenv_path)


# User Session Management
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'users.login'


# classes
class User(db.Model, UserMixin):
    """Model to define User"""
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    profile_image = db.Column(db.String(250), nullable=False,
                              default="{{ url_for('static', filename='profile_pics/default_profile.png') }}")
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(250), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy=True)
    time_inserted = db.Column(db.DateTime(), default=datetime.utcnow)
    time_updated = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, email, name, username, password='1234'):
        self.email = email
        self.name = name
        self.username = username
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""

        return {
            'email': self.id,
            'profile_image': self.profile_image,
            'email': self.email,
            'username': self.username,
            'password_hash': self.password_hash}

    def __repr__(self):
        return "Username {self.username}"


class UserAuth(db.Model, OAuthConsumerMixin):
    """Model to define UserAuth to store oAuth tokens"""
    __tablename__ = 'userauth'

    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User)


class Post(db.Model):
    """Model to define Item"""
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    title = db.Column(db.String(140), nullable=False)
    text = db.Column(db.Text, nullable=False)
    time_inserted = db.Column(db.DateTime(), default=datetime.utcnow)
    time_updated = db.Column(db.DateTime(), default=datetime.utcnow)

    def __init__(self, title, text, user_id):
        self.title = title
        self.text = text
        self.user_id = user_id

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""

        return {
            'post_id': self.id,
            'title': self.title,
            'date': self.date,
            'author name': self.author.name,
            'user_id': self.user_id,
            'text': self.text
        }

    def __repr__(self):
        return "Post Id: {self.id} " \
               "--- Date: {self.date} " \
               "--- Title: {self.title}"


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    text = TextAreaField("What's on your mind?", validators=[DataRequired()])
    submit = SubmitField('Post')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    def check_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Your email has already been registered!')

    def check_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Your username has already been registered!')


class UpdateUserForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    username = StringField('Username', validators=[DataRequired()])
    picture = FileField('Update Profile Picture',
                        validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def check_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Your email has already been registered!')

    def check_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Your username has already been registered!')


# Database
db.create_all()
db.session.commit()


# Blueprints


errorhandlers = Blueprint('errorhandlers', __name__)


@errorhandlers.app_errorhandler(404)
def error_404(error):
    """404 Not Found"""
    return render_template('errors/404.html'), 404


@errorhandlers.app_errorhandler(403)
def error_403(error):
    """403 Not Authorized"""
    return render_template('errors/403.html'), 403


@errorhandlers.app_errorhandler(500)
def error_500(error):
    """500 Server Error"""
    return render_template('errors/500.html'), 500


main = Blueprint('main', __name__)


@main.route('/')
@main.route("/home")
def index():
    """Returns all posts"""
    posts = Post.query.all()  # noqa:501
    return render_template('main.html',
                           title='Home',
                           posts=posts,
                           current_user=current_user)


@main.route('/api/v1/posts/json')
@login_required
def get_catalog():
    """Returns of all posts"""
    posts = Post.query.all()  # noqa:501
    return jsonify(post=[i.serialize for i in posts])



post = Blueprint('post', __name__)


@post.route("/post/create", methods=['GET', 'POST'])
@login_required
def create_post():
    """CREATE Post"""
    form = PostForm()
    if form.validate_on_submit():
        new_Post = Post(title=form.title.data,
                        text=form.text.data,
                        user_id=current_user.id)
        db.session.add(new_Post)
        db.session.commit()
        flash('Your Post has been successfully posted!', 'success')
        return redirect(url_for('main.index'))
    return render_template('post.html', form=form)


@post.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    """
    UPDATE Post
    :param post_id: Post_id (int) for Post
    """
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.text = form.text.data
        post.time_updated = func.now()
        db.session.commit()
        flash('Your Post has been successfully updated!', 'success')
        return redirect(url_for('post.update_post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.text.data = post.text
    return render_template('post.html', title='Update', form=form)


@post.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    """
    DELETE Post
    :param post_id: Post_id (int) for Post
    """
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your Post has been successfully deleted!', 'success')
    return redirect(url_for('main.index'))


users = Blueprint('users', __name__)


@users.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.html'))


@users.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user = User(email=form.email.data,
                    name=form.name.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Thanks for registration')
        return redirect(url_for('users.login'))
    return render_template('register.html', form=form)


@users.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if form.validate_on_submit():

        user = User.query.filter_by(email=form.email.data).first()

        if user.check_password(form.password.data) and user is not None:

            login_user(user)
            flash('Log in Success!')

            return redirect(url_for('users.account'))

    return render_template('login.html', form=form)


@users.route('/account', methods=['GET', 'POST'])
@login_required
def account():

    form = UpdateUserForm()
    if form.validate_on_submit():

        if form.picture.data:
            username = current_user.username
            pic = add_profile_pic(form.picture.data, username)
            current_user.profile_image = pic

        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('User Account Updated!')
        return redirect(url_for('users.account'))

    elif request.method == "GET":
        form.username.data = current_user.username
        form.email.data = current_user.email

    profile_image = \
        url_for('static',
                filename='profile_pics/' + current_user.profile_image)
    return render_template('account.html',
                           profile_image=profile_image, form=form)


@users.route('/<username>')
def user_posts(username):
    page = request.args.get('/page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user).\
        order_by(Post.date.desc()).pageinate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user)


userauth = Blueprint('userauth', __name__)

app.secret_key = app.config['GOOGLE_OAUTH_CLIENT_SECRET']

google_blueprint = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.secret_key,
    scope=app.config['GOOGLE_OAUTH_CLIENT_SCOPE'],
    offline=True
    )

google_blueprint.backend = SQLAlchemyBackend(UserAuth, db.session,
                                             user=current_user,
                                             user_required=False)

app.register_blueprint(google_blueprint, url_prefix="/google_login")


@userauth.route("/google_login")
def google_login():
    """redirect to Google to initiate oAuth2.0 dance"""
    if not google.authorized:
        return redirect(url_for("google.login"))
    resp = google.get("/oauth2/v2/userinfo")
    assert resp.ok, resp.text
    return resp.text


@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    """
    Receives a signal that Google has authenticated User via
    instance of blueprint and token
        1. Check response from instance of blueprint
        2. Check if user exists from db via email
        3. Create user in db if user does not exist
    """
    User = User
    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if resp.ok:
        account_info_json = resp.json()
        email = account_info_json['email']
        query = User.query.filter_by(email=email)

        try:
            user = query.one()
        except NoResultFound:
            user = User(
                name=account_info_json['email'],
                username=account_info_json['email'],
                email=account_info_json['email']
                )
            db.session.add(user)
            db.session.commit()
        login_user(user, remember=True)


@userauth.route('/google_logout')
def google_logout():
    """Revokes token and empties session."""
    if google.authorized:
        try:
            google.get(
                'https://accounts.google.com/o/oauth2/revoke',
                params={
                    'token':
                    google.token['access_token']},
            )
        except InvalidClientIdError:
            """Revokes token and empties session."""
            del google.token
            redirect(url_for('main.index'))
    session.clear()
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('main.index'))


app.register_blueprint(userauth)
app.register_blueprint(post)
app.register_blueprint(main)
app.register_blueprint(errorhandlers)
app.register_blueprint(users)




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))





def add_profile_pic(pic_upload, username):
    filename = pic_upload.filename
    ext_type = filename.split('.')[-1]
    storage_filename = str(username)+'.'+ext_type
    filepath = os.path.join(current_app.root_path, 'static/profile_pics', storage_filename)
    output_size = (120, 120)

    pic = Image.open(pic_upload)
    pic.thumbnail(output_size)
    pic.save(filepath)

    return storage_filename


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=80)
