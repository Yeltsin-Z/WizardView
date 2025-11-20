# WizardView - Local Development Guide

## 🚀 Quick Start

### **Option 1: Use the Startup Script (Easiest)**

```bash
./start.sh
```

That's it! The script will:
- ✅ Load environment variables from `.env`
- ✅ Activate your virtual environment
- ✅ Start the Flask app

Then open: http://localhost:5001

---

### **Option 2: Manual Start**

```bash
# Activate virtual environment
source venv/bin/activate

# Load environment variables
export $(cat .env | grep -v '^#' | grep -v '^$' | xargs)

# Run the app
python app.py
```

---

## 📝 Environment Variables

All your local configuration is in the `.env` file:

```bash
# Flask
SECRET_KEY=dev-secret-key-for-local-testing-only

# Linear API
LINEAR_API_KEY=lin_api_your-key-here
LINEAR_TEAM_ID=ENG

# App Config
WIZARDVIEW_URL=http://localhost:5001

# Authentication
AUTH_USERNAME=your-email@example.com
AUTH_PASSWORD=your-password-here
```

**🔒 Security Note:** `.env` is in `.gitignore` - it will NEVER be committed to git!

---

## 🛠️ Configuration

### **Change Login Credentials**

Edit `.env` and update:
```bash
AUTH_USERNAME=your-email@example.com
AUTH_PASSWORD=your-password
```

### **Use a Different Linear API Key**

Edit `.env` and update:
```bash
LINEAR_API_KEY=lin_api_your-new-key
```

### **Use Local Sample Data**

Uncomment in `.env`:
```bash
DEV_ARTIFACTS_PATH=/path/to/your/local/scrolls
```

---

## 📦 File Upload Testing

### **Test with Format 1 (Old Format)**
```
tenant/
├── main/
│   └── CHART-123.csv
└── feat/
    └── CHART-123.csv
```

### **Test with Format 2 (New Format)**
```
tenant/
├── main-CHART-123
└── feat-CHART-123
```

Both formats work automatically! ✅

---

## 🧪 Testing Workflow

1. **Start the app**: `./start.sh`
2. **Login**: http://localhost:5001
   - Username: `sdet-team@drivetrain.ai`
   - Password: `OneRing2RuleThemAll`
3. **Upload**: Drag & drop your scroll bundle ZIP
4. **Compare**: Click on files to view diffs
5. **Report Bug**: Create Linear issues with attachments

---

## 🔍 Troubleshooting

### **"Permission denied: ./start.sh"**
```bash
chmod +x start.sh
./start.sh
```

### **".env file not found"**
Make sure `.env` exists:
```bash
ls -la .env
```

If not, create it from the template:
```bash
cp env.example .env
# Edit .env with your values
```

### **"Port 5001 already in use"**
Kill existing Flask process:
```bash
lsof -ti:5001 | xargs kill -9
./start.sh
```

### **"Virtual environment not found"**
Create one:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
./start.sh
```

---

## 🔄 Keep .env in Sync

If you update environment variables in Render (production), remember to update `.env` for local development too!

**DON'T** copy production values (like SECRET_KEY) to local `.env` - keep them separate!

---

## 📚 Related Files

- `.env` - Your local environment variables (never committed)
- `env.example` - Template showing all available variables
- `start.sh` - Convenient startup script (never committed)
- `PRODUCTION_DEPLOYMENT.md` - Production deployment guide

---

## ✅ That's It!

Just run `./start.sh` and start developing! 🧙‍♂️✨

