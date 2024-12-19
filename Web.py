import shutil

##from dotenv import load_dotenv
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
app.config.from_object("config.Config")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "/tmp/uploads"
app.secret_key = "supersecretkey"
db = SQLAlchemy(app)

# 載入環境變數
##load_dotenv()
# 配置 OAuth
oauth = OAuth(app)
google = oauth.register(
    name="google",
    ##client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    ##client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    access_token_url="https://oauth2.googleapis.com/token",
    refresh_token_url=None,
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    client_kwargs={
        "scope": "openid profile email",
    },
    redirect_uri="https://webassistant-9tq4.onrender.com",  # 替换为你的回调 URI
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",  # 手動設置 JWKS URI
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
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Memo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Projects(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="待開始")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Photos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    path = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


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
    print("Redirect URI:", redirect_uri)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    try:
        token = google.authorize_access_token()
        if not token:
            flash("未能成功獲取授權憑證，請稍後再試！", "error")
            return redirect(url_for("login"))

        resp = google.get("userinfo")
        user_info = resp.json()

        # 查詢或創建用戶
        user = User.query.filter_by(username=user_info["email"]).first()
        if not user:
            # 如果該用戶不存在，則創建新帳號
            user = User(username=user_info["email"], password="")
            db.session.add(user)
            db.session.commit()

        # 設置 session 並登入
        session["user_id"] = user.id
        session["username"] = user.username  # 設置 username 到 session

        # 創建新用戶的資料庫路徑
        new_db_path = os.path.join(app.instance_path, f"{user.username}.db")

        # 如果資料庫文件不存在，則創建一個新的資料庫
        if not os.path.exists(new_db_path):
            # 需要從模板資料庫複製過來
            template_db_path = os.path.join(app.instance_path, "template.db")
            try:
                shutil.copyfile(template_db_path, new_db_path)
                app.config["SQLALCHEMY_BINDS"][
                    user.username
                ] = f"sqlite:///{new_db_path}"
                flash("帳號創建成功，並初始化資料庫！", "success")
            except FileNotFoundError:
                flash("模板資料庫不存在，請聯繫管理員。", "error")
                return redirect(url_for("login"))
        else:
            app.config["SQLALCHEMY_BINDS"][user.username] = f"sqlite:///{new_db_path}"

        flash("Google 登入成功！", "success")

        # 跳轉到 index 頁面
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"登入過程中發生錯誤：{e}", "error")
        return redirect(url_for("login"))


ALLOWED_EXTENSIONS = {"txt", "py", "js", "html", "css", "java", "xml", "json"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if User.query.filter_by(username=username).first():
            flash("使用者已存在", "error")
            return redirect(url_for("register"))

        # 創建新使用者
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        # 創建新使用者的資料庫
        new_db_path = os.path.join(app.instance_path, f"{username}.db")
        template_db_path = os.path.join(app.instance_path, "template.db")
        try:
            shutil.copyfile(template_db_path, new_db_path)
            app.config["SQLALCHEMY_BINDS"][username] = f"sqlite:///{new_db_path}"
            flash("註冊成功！", "success")
        except FileNotFoundError:
            flash("模板資料庫不存在，請聯繫管理員。", "error")
            return redirect(url_for("register"))

        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            # 設置 session 並確保成功登入
            session["user_id"] = user.id
            session["username"] = username
            flash("登入成功！", "success")
            print(f"User ID in session: {session['user_id']}")  # 偵錯輸出 session

            # 強制跳轉到 index 頁面
            return redirect(url_for("index"))
        flash("登入失敗，請檢查您的帳號和密碼。", "error")
    return render_template("login.html")


@app.before_request
def before_request():
    if request.endpoint in [
        "login",
        "register",
        "static",
        "login_google",
        "auth_callback",
    ]:
        return
    if "username" in session:
        username = session["username"]
        if username in app.config["SQLALCHEMY_BINDS"]:
            app.config["SQLALCHEMY_DATABASE_URI"] = app.config["SQLALCHEMY_BINDS"][
                username
            ]
            db.engine.dispose()  # 重新連接資料庫
        else:
            flash("無法找到對應的資料庫。", "error")
            return redirect(url_for("login"))
    else:
        return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    flash("您已成功登出。", "success")
    return redirect(url_for("login"))


# 程式碼管理
@app.route("/code", methods=["GET", "POST"])
def code_management():
    if request.method == "POST":
        title = request.form["title"]
        keywords = request.form.get("keywords", "")
        file = request.files["file"]

        if file and allowed_file(file.filename):
            filename = file.filename
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            snippet = CodeSnippets(
                title=title,
                filepath=filename,
                keywords=keywords,
                user_id=session["user_id"],
            )
            db.session.add(snippet)
            db.session.commit()
            flash("程式碼片段已新增。", "success")
            return redirect(url_for("code_management"))
        else:
            flash("檔案類型不支援，請上傳允許的檔案格式！", "error")

    snippets = CodeSnippets.query.filter_by(user_id=session["user_id"]).all()
    return render_template("code.html", snippets=snippets)


@app.route("/download/<filename>")
def download_code(filename):
    return send_from_directory(
        app.config["UPLOAD_FOLDER"], filename, as_attachment=True
    )


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
        memo = Memo(content=content, user_id=session["user_id"])
        db.session.add(memo)
        db.session.commit()
        flash("備忘錄已新增。", "success")
        return redirect(url_for("memo_management"))

    memos = Memo.query.filter_by(user_id=session["user_id"]).all()
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
        project = Projects(
            name=name,
            description=description,
            status=status,
            user_id=session["user_id"],
        )
        db.session.add(project)
        db.session.commit()
        flash("專案已新增。", "success")
        return redirect(url_for("project_management"))

    projects = Projects.query.filter_by(user_id=session["user_id"]).all()
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
            photo = Photos(
                filename=filename,
                path=filepath,
                category=category,
                user_id=session["user_id"],
            )
            db.session.add(photo)
            db.session.commit()
            flash("相片已新增。", "success")
            return redirect(url_for("photo_management"))

    photos = Photos.query.filter_by(user_id=session["user_id"]).all()
    return render_template("photos.html", photos=photos)


@app.route("/photos/delete/<int:id>", methods=["POST"])
def delete_photo(id):
    photo = Photos.query.get_or_404(id)
    try:
        os.remove(photo.path)  # 刪除檔案
    except OSError as e:
        print(f"Error: {e.strerror}")
    db.session.delete(photo)
    db.session.commit()
    flash("相片已刪除。", "success")
    return redirect(url_for("photo_management"))


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/download/photo/<filename>")
def download_photo(filename):
    return send_from_directory(
        app.config["UPLOAD_FOLDER"], filename, as_attachment=True
    )


@app.route("/reset", methods=["POST"])
def reset_database():
    db.drop_all()
    db.create_all()
    return redirect(url_for("index"))


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    if not os.path.exists(app.config["UPLOAD_FOLDER"]):
        os.makedirs(app.config["UPLOAD_FOLDER"])
    app.run(debug=True)
