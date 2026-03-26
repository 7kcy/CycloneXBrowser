# 🌀 Cyclone X — Vercel Edition

## File Structure
```
CycloneX-Vercel/
├── api/
│   └── search.js       ← Serverless function (handles API calls)
├── public/
│   └── index.html      ← Frontend
├── vercel.json         ← Vercel config
└── README.txt
```

## Deploy Steps

### 1. Upload to GitHub
- Go to github.com → New repository → name it "cyclone-x"
- Upload ALL files keeping the folder structure above
  (api/ folder, public/ folder, vercel.json at root)

### 2. Connect to Vercel
- Go to vercel.com → Add New Project → Import your GitHub repo
- Framework Preset: select "Other"
- Root Directory: leave as "/"
- Click Deploy

### 3. Add your API Key (IMPORTANT)
- In Vercel dashboard → Your project → Settings → Environment Variables
- Add: Name = ANTHROPIC_API_KEY, Value = sk-ant-YOUR_KEY_HERE
- Click Save
- Go to Deployments → click the 3 dots → Redeploy

### 4. Done!
Your site is live and search works. Key is safe on the server — never exposed to users.

## Add Your Logo
Upload CyLogo_png.png into the public/ folder.
