class Config:
    SECRET_KEY = "your_secret_key"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///default.db"  # 預設資料庫
    SQLALCHEMY_BINDS = {
        "template": "sqlite:///template.db",  # 模板資料庫
        # 其他使用者的資料庫連接將動態添加
    }
