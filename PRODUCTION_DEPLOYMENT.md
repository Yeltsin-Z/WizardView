# WizardView Production Deployment Guide

## 🚀 **Pre-Deployment Checklist**

### ✅ **Required Environment Variables**

Before deploying to production (Render, AWS, etc.), you **MUST** set these environment variables:

#### **1. SECRET_KEY** (CRITICAL)
```bash
# Generate a secure random key:
python -c "import secrets; print(secrets.token_hex(32))"

# Set in Render:
SECRET_KEY=your-generated-key-here
```
⚠️ **WARNING**: App will fail to start if not set in production!

#### **2. LINEAR_API_KEY** (Required for Linear integration)
```bash
LINEAR_API_KEY=lin_api_your-actual-key-here
```
Get your key from: https://linear.app/settings/api

#### **3. LINEAR_TEAM_ID** (Required)
```bash
LINEAR_TEAM_ID=ENG
```
Your Linear team identifier (e.g., ENG, PRODUCT, etc.)

#### **4. WIZARDVIEW_URL** (Required)
```bash
WIZARDVIEW_URL=https://your-app.onrender.com
```
Your deployed application URL (for Linear links back to the app)

#### **5. AUTH_USERNAME** (Recommended)
```bash
AUTH_USERNAME=your-team-email@company.com
```
Change from default: `sdet-team@drivetrain.ai`

#### **6. AUTH_PASSWORD** (Recommended)
```bash
AUTH_PASSWORD=your-secure-password
```
Change from default: `OneRing2RuleThemAll`

---

## 📦 **Render Deployment**

### **Step 1: Create Web Service**
1. Go to Render dashboard
2. Click "New +" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - **Name**: wizardview
   - **Branch**: main
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app -c gunicorn_config.py`

### **Step 2: Set Environment Variables**
In Render dashboard → Your Service → Environment:

```bash
SECRET_KEY=<generated-key>
LINEAR_API_KEY=lin_api_<your-key>
LINEAR_TEAM_ID=ENG
WIZARDVIEW_URL=https://wizardview.onrender.com
AUTH_USERNAME=your-email@company.com
AUTH_PASSWORD=your-secure-password
```

### **Step 3: Deploy**
- Render will auto-deploy on every push to `main`
- Or manually trigger: Dashboard → Manual Deploy → Deploy latest commit

---

## 🔒 **Security Checklist**

- [ ] SECRET_KEY is set to a strong random value
- [ ] AUTH_USERNAME changed from default
- [ ] AUTH_PASSWORD changed from default  
- [ ] LINEAR_API_KEY is kept secret (not in code)
- [ ] `.env` file is in `.gitignore` (never commit!)
- [ ] Using HTTPS in production (Render provides this automatically)

---

## 🧪 **Testing Production Deployment**

### **1. Check Health Endpoint**
```bash
curl https://your-app.onrender.com/health
```
Should return:
```json
{
  "service": "WizardView",
  "status": "healthy",
  "version": "1.0"
}
```

### **2. Check Configuration**
Watch the deployment logs for warnings:
```
⚠️  PRODUCTION CONFIGURATION WARNINGS:
   • Using default AUTH_USERNAME - change in production!
   • Using default AUTH_PASSWORD - change in production!
```

### **3. Test Upload**
1. Login at: `https://your-app.onrender.com/login`
2. Upload a scroll bundle ZIP
3. View comparison

### **4. Test Linear Integration**
1. Compare files
2. Click "Report Bug"
3. Create issue
4. Verify issue appears in Linear with attachment

---

## 📝 **Configuration Reference**

### **Environment Variables (All Options)**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | **Yes** | None (dev only) | Flask session secret |
| `LINEAR_API_KEY` | **Yes** | None | Linear API authentication |
| `LINEAR_TEAM_ID` | **Yes** | `ENG` | Linear team ID |
| `WIZARDVIEW_URL` | **Yes** | `https://wizardview.onrender.com` | App URL for links |
| `AUTH_USERNAME` | Recommended | `sdet-team@drivetrain.ai` | Login username |
| `AUTH_PASSWORD` | Recommended | `OneRing2RuleThemAll` | Login password |
| `PORT` | No | `5001` | Server port (Render sets automatically) |
| `ARTIFACTS_DIR` | No | `uploads/extracted` | Custom artifacts directory |
| `DEV_ARTIFACTS_PATH` | No | None | Development: Override artifacts path |
| `SAMPLE_SCROLLS_PATH` | No | None | Development: Sample scrolls for testing |
| `FLASK_ENV` | No | `production` | Flask environment |

---

## 🐛 **Troubleshooting**

### **App won't start**
```
ValueError: SECRET_KEY environment variable must be set in production!
```
**Solution**: Set `SECRET_KEY` in environment variables

### **Linear integration not working**
```
Linear API key not configured
```
**Solution**: Set `LINEAR_API_KEY` and `LINEAR_TEAM_ID`

### **Files not uploading**
- Check Render logs for errors
- Verify disk space (Render free tier has limited storage)
- Try uploading smaller ZIP files first

### **Session expires immediately**
- Verify `SECRET_KEY` is set correctly
- Check if cookies are enabled in browser
- Ensure HTTPS is being used

---

## 📊 **Monitoring**

### **Check Application Logs**
```bash
# In Render dashboard
Your Service → Logs → View logs
```

### **Watch for Warnings**
Look for configuration warnings on startup:
```
⚠️  PRODUCTION CONFIGURATION WARNINGS:
```

### **Monitor Resource Usage**
- CPU usage should be low (< 50%)
- Memory usage depends on upload size
- Disk usage grows with uploaded artifacts

---

## 🔄 **Updating**

### **Deploy New Version**
```bash
git add .
git commit -m "Your changes"
git push origin main
```
Render will auto-deploy within 1-2 minutes.

### **Rollback**
In Render dashboard:
1. Go to Your Service → Deploys
2. Find previous working deploy
3. Click "..." → Redeploy

---

## 📞 **Support**

For issues or questions:
1. Check application logs in Render dashboard
2. Review this deployment guide
3. Check `env.example` for configuration reference
4. Verify all environment variables are set correctly

---

## ✅ **Production Ready!**

Once all environment variables are set and the app starts without warnings, WizardView is ready for production use! 🎉

