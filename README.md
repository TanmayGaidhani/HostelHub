# HostelHub - Smart Hostel Management System

A comprehensive Flask-based web application for managing hostel operations, including student registration, mess management, room allocation, fee payments, and administrative tasks.

## 🚀 Features

### Student Features
- **Registration & Login** - Streamlined registration without OTP verification
- **Daily Attendance** - Mark daily attendance for mess
- **Mess Leave** - Apply for mess leave on future dates
- **Bill Payment** - Integrated Razorpay payment system
- **Leave Applications** - Submit hostel leave requests
- **Feedback & Complaints** - Submit feedback and complaints with media
- **Profile Management** - Update personal information and profile picture
- **Notifications** - Receive important announcements

### Admin Features
- **Student Approval** - Approve/decline new registrations
- **Room Allocation** - Assign rooms to students (F-01 to F-200, G-01 to G-300)
- **Attendance Tracking** - View daily attendance reports
- **Fee Management** - Set monthly bills and track payments
- **Timetable Management** - Update mess schedules
- **Complaint Management** - Handle student complaints
- **User Management** - View and manage all users

### Hostel Admin Features
- **Hostel Fee Management** - Set and track hostel fees
- **Room Overview** - Monitor room occupancy
- **Payment Tracking** - Track hostel fee payments

## 🛠️ Technology Stack

- **Backend**: Flask (Python)
- **Database**: MongoDB Atlas
- **Authentication**: Flask-Login with session management
- **Payment**: Razorpay integration
- **Email**: Flask-Mail for notifications
- **Forms**: WTForms with validation
- **Security**: bcrypt password hashing
- **Frontend**: HTML5, CSS3, JavaScript
- **UI Framework**: Bootstrap 5

## 📋 Prerequisites

- Python 3.8+
- MongoDB Atlas account
- Razorpay account (for payments)
- Gmail account (for email notifications)

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/TanmayGaidhani/HostelHub.git
   cd HostelHub
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   # or
   source venv/bin/activate  # Linux/Mac
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure application**
   ```bash
   cp config.template.json config.json
   ```
   
   Edit `config.json` with your credentials:
   - MongoDB connection string
   - Gmail credentials
   - Razorpay API keys
   - Secret keys

5. **Initialize database**
   ```bash
   python add_mess_admin.py
   python add_hostel_admin.py
   python add_fake_users.py  # Optional: Add test users
   ```

6. **Run the application**
   ```bash
   python main.py
   ```

7. **Access the application**
   - Open http://localhost:5000 in your browser

## 👥 Default Admin Accounts

### Mess Admin
- **Email**: `messtrack@admin.com`
- **Password**: `messtrackadmin`
- **Access**: Mess management, timetables, attendance

### Hostel Admin
- **Email**: `hosteladmin@hostelhub.ac.in`
- **Password**: `messtrackadmin`
- **Access**: Room allocation, hostel fees, user management

## 🔐 Security Features

- **Session Management** - 20-minute timeout with secure cookies
- **Password Security** - bcrypt hashing with multiple algorithm support
- **CAPTCHA Protection** - Login forms protected with CAPTCHA
- **Input Validation** - Comprehensive form validation
- **CSRF Protection** - WTForms CSRF tokens
- **Role-based Access** - Separate admin and student areas

## 📱 Key Improvements

### Recent Updates
- ✅ **Removed OTP verification** from registration for better UX
- ✅ **Enhanced forgot password** system with 3-step security verification
- ✅ **Updated footers** across all pages
- ✅ **Improved UI/UX** with modern design and animations
- ✅ **Better error handling** and user feedback
- ✅ **Security enhancements** with proper credential management

## 🗂️ Project Structure

```
HostelHub/
├── main.py                 # Main Flask application
├── config.json            # Configuration (not in repo)
├── config.template.json    # Configuration template
├── requirements.txt        # Python dependencies
├── static/                 # CSS, JS, images
├── templates/              # HTML templates
├── add_*.py               # Database initialization scripts
└── README.md              # This file
```

## 🚀 Deployment

For production deployment:

1. **Set environment variables** instead of config.json
2. **Use production WSGI server** (Gunicorn, uWSGI)
3. **Enable HTTPS** and set secure cookies
4. **Configure proper MongoDB security**
5. **Set up backup strategies**

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 👨‍💻 Authors

**Designed and Developed by Tanmay and Nikhil**

## 📞 Support

For support and queries, contact the development team or create an issue on GitHub.

---

© 2025 HostelHub • Designed by Tanmay and Nikhil