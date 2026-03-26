# 🌀 Cyclone X

AI-powered search engine. Runs locally in your browser.

---

## ⚡ Setup (takes ~2 minutes)

### Step 1 — Install Node.js
If you don't have it: https://nodejs.org → download the **LTS** version and install it.

### Step 2 — Get your Anthropic API key
1. Go to https://console.anthropic.com
2. Sign up / log in
3. Click **API Keys** → **Create Key**
4. Copy the key (starts with `sk-ant-...`)

### Step 3 — Unzip and install
Unzip this folder, open a terminal inside it, then run:

```
npm install
```

### Step 4 — Set your API key and start

**On Mac / Linux:**
```
ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE npm start
```

**On Windows (Command Prompt):**
```
set ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE && npm start
```

**On Windows (PowerShell):**
```
$env:ANTHROPIC_API_KEY="sk-ant-YOUR_KEY_HERE"; npm start
```

### Step 5 — Open in browser
Go to: **http://localhost:3000**

That's it! Search away 🌀

---

## 🖼️ Logo
Drop your `CyLogo_png.png` into the `public/` folder to show your logo.

---

## 📁 File Structure
```
CycloneX/
├── server.js          ← Express backend (proxies API calls)
├── package.json
└── public/
    ├── index.html     ← Frontend
    ├── index.js       ← Frontend logic
    ├── styles.css     ← All styling
    └── CyLogo_png.png ← Your logo (add this)
```
