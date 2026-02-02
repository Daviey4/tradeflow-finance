# TradeFlow Mobile - Pure Python 🐍

Build iOS, Android, Web, and Desktop apps with **100% Python** - no JavaScript required!

Built with [Flet](https://flet.dev) - Flutter apps in Python.

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Locally
```bash
python tradeflow_app.py
```

### 3. Run as Web App
```bash
flet run --web tradeflow_app.py
```

---

## 📱 Build for Mobile

### Android APK
```bash
# Install Android SDK first, then:
flet build apk

# Output: build/apk/app-release.apk
```

### iOS IPA (requires Mac)
```bash
# Install Xcode first, then:
flet build ipa

# Output: build/ipa/
```

### Web App
```bash
flet build web

# Output: build/web/
# Deploy to any static hosting (Netlify, Vercel, GitHub Pages)
```

### Windows EXE
```bash
flet build windows
```

### macOS App
```bash
flet build macos
```

---

## 🔧 Configuration

Edit `tradeflow_app.py` and update:

```python
# Change to your deployed Django server
API_BASE_URL = "https://your-tradeflow-server.com"
```

---

## 📂 Project Structure

```
mobile-python/
├── tradeflow_app.py    # Main application (single file!)
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── assets/            # Icons and images (optional)
    ├── icon.png
    └── splash.png
```

---

## 🎨 Customization

### Colors
Edit the `COLORS` dictionary:
```python
COLORS = {
    "background": "#000000",
    "primary": "#22c55e",  # Green
    "danger": "#ef4444",   # Red
    # ...
}
```

### Assets
Add more cryptocurrencies:
```python
ASSETS = [
    {"id": "bitcoin", "symbol": "BTC", "name": "Bitcoin"},
    {"id": "dogecoin", "symbol": "DOGE", "name": "Dogecoin"},
    # Add more...
]
```

---

## 🆚 Why Flet vs React Native?

| Feature | Flet (Python) | React Native (JS) |
|---------|---------------|-------------------|
| Language | Python 🐍 | JavaScript |
| Learning Curve | Easy (you know Python!) | Medium |
| Performance | Good (Flutter engine) | Good |
| Native Look | Yes (Material/Cupertino) | Yes |
| Single Codebase | ✅ | ✅ |
| Hot Reload | ✅ | ✅ |
| Desktop Support | ✅ | ❌ (needs Electron) |
| Web Support | ✅ | ✅ (React Native Web) |
| Community | Growing | Large |

---

## 📚 Learn More

- [Flet Documentation](https://flet.dev/docs/)
- [Flet Examples](https://github.com/flet-dev/examples)
- [Flutter Widgets Reference](https://docs.flutter.dev/ui/widgets)

---

## 🐛 Troubleshooting

### "Module not found: flet"
```bash
pip install flet --upgrade
```

### Android build fails
```bash
# Make sure Android SDK is installed
# Set ANDROID_HOME environment variable
export ANDROID_HOME=$HOME/Android/Sdk
```

### iOS build fails
```bash
# Xcode and CocoaPods required
xcode-select --install
sudo gem install cocoapods
```

---

## 🎯 Your Python Skills → Mobile Apps

Since you already know:
- ✅ Python
- ✅ Django
- ✅ REST APIs
- ✅ Database modeling

You can now build:
- 📱 iOS apps
- 🤖 Android apps
- 🌐 Web apps
- 🖥️ Desktop apps

All in Python! No JavaScript needed.

---

Built with ❤️ by David Alicea
