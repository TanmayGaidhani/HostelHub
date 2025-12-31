# HostelHub Deployment Guide for Render

## 🚀 Deploy to Render

### Prerequisites
1. GitHub account with your HostelHub repository
2. Render account (free tier available)
3. MongoDB Atlas database
4. API keys for Razorpay, Gmail, Twilio

### Step-by-Step Deployment

#### 1. **Prepare Your Repository**
- Ensure all files are committed and pushed to GitHub
- Verify `render.yaml`, `Procfile`, and `runtime.txt` are present

#### 2. **Create New Web Service on Render**
1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New +" → "Web Service"
3. Connect your GitHub repository: `TanmayGaidhani/HostelHub`
4. Configure the service:
   - **Name**: `hostelhub`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python main.py`

#### 3. **Set Environment Variables**
In Render dashboard, go to Environment tab and add:

```
MONGO_URI=mongodb+srv://username:password@cluster0.xwnlb7q.mongodb.net/atls?appName=Cluster0
SECRET_KEY=your-secret-key-here
GMAIL_USER=your-email@gmail.com
GMAIL_PASSWORD=your-app-password
RAZORPAY_KEY_ID=your-razorpay-key-id
RAZORPAY_KEY_SECRET=your-razorpay-key-secret
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_NUMBER=your-twilio-number
```

#### 4. **Deploy**
- Click "Create Web Service"
- Render will automatically build and deploy your app
- Wait for deployment to complete (5-10 minutes)

#### 5. **Access Your App**
- Your app will be available at: `https://hostelhub.onrender.com`
- Or your custom domain if configured

### 🔧 Environment Variables Details

| Variable | Description | Example |
|----------|-------------|---------|
| `MONGO_URI` | MongoDB Atlas connection string | `mongodb+srv://user:pass@cluster.mongodb.net/db` |
| `SECRET_KEY` | Flask secret key for sessions | `your-random-secret-key` |
| `GMAIL_USER` | Gmail address for notifications | `your-email@gmail.com` |
| `GMAIL_PASSWORD` | Gmail app password | `your-app-password` |
| `RAZORPAY_KEY_ID` | Razorpay API key ID | `rzp_test_xxxxx` |
| `RAZORPAY_KEY_SECRET` | Razorpay API secret | `your-razorpay-secret` |
| `TWILIO_ACCOUNT_SID` | Twilio account SID | `ACxxxxx` |
| `TWILIO_AUTH_TOKEN` | Twilio auth token | `your-twilio-token` |
| `TWILIO_NUMBER` | Twilio phone number | `+1234567890` |

### 🔒 Security Notes

1. **HTTPS**: Render provides free SSL certificates
2. **Environment Variables**: Never commit sensitive data to Git
3. **Database**: Use MongoDB Atlas with proper authentication
4. **Sessions**: Secure cookies enabled for production

### 🐛 Troubleshooting

#### Common Issues:
1. **Build Fails**: Check `requirements.txt` for incompatible packages
2. **App Won't Start**: Verify `PORT` environment variable usage
3. **Database Connection**: Check MongoDB Atlas IP whitelist (allow all: 0.0.0.0/0)
4. **Static Files**: Ensure static files are properly served

#### Logs:
- Check Render logs in dashboard for detailed error messages
- Use `print()` statements for debugging (visible in logs)

### 📊 Monitoring

- **Health Checks**: Render automatically monitors your app
- **Logs**: Available in Render dashboard
- **Metrics**: CPU, memory usage visible in dashboard

### 🔄 Updates

To update your deployed app:
1. Push changes to GitHub
2. Render will automatically redeploy
3. Or manually trigger deployment in dashboard

### 💰 Pricing

- **Free Tier**: 750 hours/month, sleeps after 15 minutes of inactivity
- **Paid Plans**: Starting at $7/month for always-on service

### 🎯 Post-Deployment Tasks

1. **Initialize Database**: Run admin creation scripts
2. **Test All Features**: Registration, login, payments, etc.
3. **Configure Domain**: Optional custom domain setup
4. **Set up Monitoring**: Error tracking and performance monitoring

---

## 📞 Support

If you encounter issues:
1. Check Render documentation
2. Review application logs
3. Verify environment variables
4. Test database connectivity

**Happy Deploying! 🚀**