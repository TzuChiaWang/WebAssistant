# WebAssistant 網站助手

這是一個基於Flask開發的網站助手應用程式，提供多種實用功能來協助使用者管理其數位資源。

## 主要功能

- 🔐 Google OAuth 登入系統
- 📝 程式碼片段管理
- 📋 備忘錄管理
- 📊 專案管理
- 📸 相片管理

## 技術架構

- 後端框架：Flask
- 資料庫：SQLAlchemy
- 認證：Google OAuth 2.0
- 前端：HTML, CSS, JavaScript

## 安裝與設定

1. 安裝所需套件：
```bash
pip install -r requirements.txt
```

2. 設定環境變數：
在 `.env` 檔案中設定以下變數：
```
GOOGLE_CLIENT_ID=你的Google客戶端ID
GOOGLE_CLIENT_SECRET=你的Google客戶端密鑰
```

3. 初始化資料庫：
應用程式會在首次運行時自動建立所需的資料表。

## 運行應用程式

```bash
python Web.py
```

## 功能說明

### 程式碼管理
- 上傳並管理程式碼片段
- 支援多種程式語言檔案
- 可下載和刪除已儲存的程式碼

### 備忘錄管理
- 建立和管理個人備忘錄
- 時間戳記功能
- 簡單的增刪改查操作

### 專案管理
- 建立和追蹤專案進度
- 專案狀態管理
- 專案描述和細節記錄

### 相片管理
- 上傳和管理相片
- 支援多種圖片格式
- 相片分類功能

## 安全性

- 使用 Google OAuth 2.0 進行身份驗證
- 密碼安全雜湊儲存
- 檔案上傳安全性驗證

## 部署資訊

應用程式目前部署在 Render 平台上：
https://webassistant-9tq4.onrender.com
