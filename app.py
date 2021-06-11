from flask import Flask
from flask import render_template, request, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import os
import boto3
from datetime import timedelta
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Session config
app.secret_key = "random key"
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
# Image Config
app.config["IMAGES_UPLOAD"] = "/home/freewill/Desktop/uploadImage/static/upload"
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["JPEG", "JPG", "PNG", "GIF"]


# oAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id="enter the client id",
    client_secret="enter the client secret key",
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)


@app.route("/")
@limiter.limit("5 per minute")
def hello_world():
    return render_template("login.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/authorize')
def authorize():
    google = oauth.create_client('google') 
    token = google.authorize_access_token()

    resp = google.get('userinfo')
    user_info = resp.json()
    user = oauth.google.userinfo()  
    session['profile'] = user_info

    session.permanent = True
    return redirect('/upload-image')


# -------------------------S3 bucket--------------
mymebucket = os.environ.get('S3_bucket')
s3 = boto3.client('s3')


def allowed_image(filename):
    if not "." in filename:
        return False

    ext = filename.rsplit(".", 1)[1]
    if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        False


@app.route("/upload-image", methods=['GET', 'POST'])
def uploadImage():

    if request.method == 'POST':

        if request.files:
            image = request.files['Image']

        if image.filename == "":
            print("Image must have a filename")
            return redirect(request.url)

        if not allowed_image(image.filename):
            print("That image extension is not allowed.")
        else:
            filename1 = secure_filename(image.filename)

        s3.put_object(
            Body=image,
            Bucket="mymebucket",
            Key=filename1
        )
        return render_template("response.html", imageName=filename1)

    email = dict(session)['profile']['email']
    return render_template("uploadImage.html", yourName=email)


@app.route('/display/<filename>')
def display_image(filename):
    url = s3.generate_presigned_url('get_object', Params={
        'Bucket': 'mymebucket', 'Key': filename}, ExpiresIn=1200)
    return redirect(url, code=302)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    for key in list(session.keys()):
        session.pop(key)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
