from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    send_from_directory,
    session,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import os
from datetime import datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///personal_assistant.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "uploads"
app.secret_key = "supersecretkey"
db = SQLAlchemy(app)

# 配置 OAuth
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id="YOUR_GOOGLE_CLIENT_ID",
    client_secret="YOUR_GOOGLE_CLIENT_SECRET",
    access_token_url="https://accounts.google.com/o/oauth2/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    authorize_redirect_uri="http://localhost:5000/auth/callback",
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    client_kwargs={"scope": "openid profile email"},
)


# 資料庫模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class CodeSnippets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    filepath = db.Column(db.String(200), nullable=False)  # 存檔案路徑
    keywords = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Memo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Projects(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="待開始")


class Photos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    path = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=True)


# 初始化資料庫
with app.app_context():
    db.create_all()


# 主頁
@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("index.html")


# Google OAuth 登入
@app.route("/login/google")
def login_google():
    redirect_uri = url_for("auth_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    token = google.authorize_access_token()
    resp = google.get("userinfo")
    user_info = resp.json()
    user = User.query.filter_by(username=user_info["email"]).first()
    if not user:
        user = User(username=user_info["email"], password="")
        db.session.add(user)
        db.session.commit()
    session["user_id"] = user.id
    flash("Google 登入成功！", "success")
    return redirect(url_for("index"))


ALLOWED_EXTENSIONS = {"txt", "py", "js", "html", "css", "java", "cpp"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("註冊成功！請登入。")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            flash("登入成功！")
            return redirect(url_for("index"))
        else:
            flash("登入失敗，請檢查您的帳號和密碼。")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("您已登出。")
    return redirect(url_for("login"))


# 程式碼管理
@app.route("/code", methods=["GET", "POST"])
def code_management():
    if request.method == "POST":
        title = request.form["title"]
        keywords = request.form.get("keywords", "")
        file = request.files["file"]

        # 檢查是否有檔案以及檔案類型是否合法
        if file and allowed_file(file.filename):
            filename = file.filename
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)  # 儲存檔案

            snippet = CodeSnippets(title=title, filepath=filepath, keywords=keywords)
            db.session.add(snippet)
            db.session.commit()
            return redirect(url_for("code_management"))
        else:
            return "檔案類型不支援，請上傳允許的檔案格式！", 400

    snippets = CodeSnippets.query.all()
    return render_template("code.html", snippets=snippets)


@app.route("/code/delete/<int:id>", methods=["POST"])
def delete_code(id):
    snippet = CodeSnippets.query.get_or_404(id)
    db.session.delete(snippet)
    db.session.commit()
    flash("程式碼片段已刪除。", "success")
    return redirect(url_for("code_management"))


# 備忘錄管理
@app.route("/memo", methods=["GET", "POST"])
def memo_management():
    if request.method == "POST":
        content = request.form["content"]
        memo = Memo(content=content)
        db.session.add(memo)
        db.session.commit()
        return redirect(url_for("memo_management"))
    memos = Memo.query.all()
    return render_template("memo.html", memos=memos)


@app.route("/memo/delete/<int:id>", methods=["POST"])
def delete_memo(id):
    memo = Memo.query.get_or_404(id)
    db.session.delete(memo)
    db.session.commit()
    flash("備忘錄已刪除。", "success")
    return redirect(url_for("memo_management"))


# 專案管理
@app.route("/projects", methods=["GET", "POST"])
def project_management():
    if request.method == "POST":
        name = request.form["name"]
        description = request.form.get("description", "")
        status = request.form.get("status", "待開始")
        project = Projects(name=name, description=description, status=status)
        db.session.add(project)
        db.session.commit()
        return redirect(url_for("project_management"))
    projects = Projects.query.all()
    return render_template("projects.html", projects=projects)


@app.route("/projects/delete/<int:id>", methods=["POST"])
def delete_project(id):
    project = Projects.query.get_or_404(id)
    db.session.delete(project)
    db.session.commit()
    flash("專案已刪除。", "success")
    return redirect(url_for("project_management"))


# 相片管理
@app.route("/photos", methods=["GET", "POST"])
def photo_management():
    if request.method == "POST":
        file = request.files["file"]
        category = request.form.get("category", "未分類")
        if file:
            filename = file.filename
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            photo = Photos(filename=filename, path=filepath, category=category)
            db.session.add(photo)
            db.session.commit()
            return redirect(url_for("photo_management"))
    photos = Photos.query.all()
    return render_template("photos.html", photos=photos)


@app.route("/photos/delete/<int:id>", methods=["POST"])
def delete_photo(id):
    photo = Photos.query.get_or_404(id)
    db.session.delete(photo)
    db.session.commit()
    flash("相片已刪除。", "success")
    return redirect(url_for("photo_management"))


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/reset", methods=["POST"])
def reset_database():
    db.drop_all()
    db.create_all()
    return redirect(url_for("index"))


if __name__ == "__main__":
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])
    app.run(debug=True)
