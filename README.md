# 📝 NoteNest

NoteNest is a secure and modern note-taking web application built with **Flask**.  
It allows users to create, edit, and manage personal notes with authentication powered by **JWT** and **Google OAuth**.  
The project demonstrates secure login, session management, and database integration.

---

## 🚀 Features

- ✍️ **Create, Edit, Delete Notes** – Manage personal notes with an intuitive UI.  
- 🔒 **Secure Authentication** –  
  - **JWT (JSON Web Token)** for protecting routes.  
  - **Google OAuth 2.0** for signing in with your Google account.  
- 📧 **Email Support** – Integrated OTP functionality via Gmail SMTP.  
- 🍪 **Secure Cookies** – Tokens stored in HTTP-only cookies for safety.  
- 🗄️ **SQLite Database** – Lightweight and persistent storage for users and notes.  
- 🎨 **Responsive UI** – Clean and minimal design with HTML/CSS.  

---

## 🛠️ Tech Stack

- **Backend:** Flask (Python)  
- **Authentication:** JWT, Google OAuth 2.0  
- **Database:** SQLite  
- **Mailing:** Flask-Mail (SMTP with Gmail)  
- **Frontend:** HTML, CSS  
- **Environment Management:** python-dotenv  

---

## 📂 Project Setup

### 1️⃣ Clone or Fork the Repo
```bash
# Clone this repo
git clone https://github.com/your-username/NoteNest.git

# Or fork and then clone your fork
```

2️⃣ Navigate to the Project
```bash
cd NoteNest
```

3️⃣ Create a Virtual Environment
```bash
# Windows
python -m venv venv

# macOS/Linux
python3 -m venv venv
```

4️⃣ Activate the Virtual Environment
```bash
# Windows (PowerShell)
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

5️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

6️⃣ Configure Environment Variables
Create a .env file in the project root with the following keys:

```bash
# Flask
SECRET_KEY=supersecretkey

# JWT
JWT_SECRET_KEY=super-secret-key

# Mail
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://127.0.0.1:5000/callback

# Database
DB_NAME=notes.db
```
⚠️ Important: Never commit your .env file to GitHub. It should stay private.

7️⃣ Run the App
```bash
flask run

or

python app.py
```

📌 Usage
- Register or login using email & password.
- Or login securely via Google Sign-In.
- Create, update, or delete your notes.
- Notes are user-specific and protected via JWT authentication.

🤝 Contributing
Feel free to fork this repo, open issues, and submit pull requests to improve NoteNest.

💡 Made with Flask and ❤️ for learning secure web app development.
