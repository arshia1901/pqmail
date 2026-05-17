# PQMail React Frontend (Module 7)

Modern interactive dashboard for the PQMail post-quantum email gateway.

## Features

✨ **Real-time Email Feed** - Live WebSocket connection to backend
📊 **Risk Visualization** - Distribution charts for algorithms and risk categories
📤 **Audit Uploader** - Drag-and-drop .mbox file auditing
🎯 **Risk Badges** - Color-coded risk levels (CRITICAL/HIGH/MEDIUM/LOW)
🔐 **Algorithm Display** - Shows email encryption method (HYBRID/ECDH/RSA/UNENCRYPTED)
📈 **Statistics Dashboard** - Real-time metrics on processed emails

## Quick Start

```bash
cd frontend

# Install dependencies
npm install

# Start dev server (http://localhost:5173)
npm run dev

# Build for production
npm run build

# Preview production build
npm preview
```

## Architecture

### Components

**Dashboard.tsx** - Main component with:
- Real-time WebSocket connection to `ws://localhost:8000/ws/events`
- Live email feed display (20 most recent)
- Statistics cards (total, critical, hybrid, avg safety)
- Audit uploader (drag & drop .mbox files)
- Algorithm distribution chart
- Risk distribution chart

### Technologies

- **React 18** - UI framework
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first styling
- **Lucide React** - Icon components
- **Vite** - Lightning-fast bundler
- **WebSocket** - Real-time backend communication

### Color Scheme

| Status | Color |
|--------|-------|
| CRITICAL | Red (#EF4444) |
| HIGH | Orange (#F97316) |
| MEDIUM | Yellow (#EAB308) |
| LOW | Green (#22C55E) |

| Algorithm | Color |
|-----------|-------|
| HYBRID | Purple (#9333EA) |
| ECDH | Blue (#3B82F6) |
| RSA | Indigo (#4F46E5) |
| UNENCRYPTED | Red (#EF4444) |

## Event Schema (WebSocket)

```typescript
interface Email {
  timestamp: string;           // ISO8601 timestamp
  message_id: string;          // Message ID from email
  from: string;                // Sender email
  to: string[];                // Recipient emails
  algorithm: string;           // HYBRID, ECDH, RSA, UNENCRYPTED, etc.
  sensitivity: string;         // CRITICAL, HIGH, MEDIUM, LOW
  risk: {
    risk_category: string;     // CRITICAL, HIGH, MEDIUM, LOW
    years_of_safety_remaining: number;  // HNDL score
  };
  action: string;              // UPGRADE, FORWARD, FLAG
  flag?: string;               // Reason if flagged
}
```

## API Integration

**Backend URL:** `http://localhost:8000`

### Endpoints Used

- **GET /health** - Check backend status
- **GET /config** - Retrieve configuration
- **POST /audit/upload** - Upload .mbox file
- **WS /ws/events** - Real-time event stream

## Development

### File Structure

```
frontend/
├── src/
│   ├── Dashboard.tsx        # Main dashboard component
│   ├── App.tsx              # App root
│   ├── main.tsx             # React entry point
│   └── index.css            # Global styles + Tailwind
├── index.html               # HTML template
├── vite.config.ts           # Vite configuration
├── tsconfig.json            # TypeScript configuration
├── tailwind.config.js       # Tailwind CSS configuration
├── postcss.config.js        # PostCSS configuration
└── package.json             # Dependencies
```

### Running Alongside Backend

**Terminal 1 (Backend):**
```bash
cd pqmail
python run_backend.py
# Server at http://localhost:8000
```

**Terminal 2 (Frontend):**
```bash
cd pqmail/frontend
npm run dev
# Server at http://localhost:5173
```

Then open http://localhost:5173 in your browser.

## Deployment

### Build for Production

```bash
npm run build
# Output: dist/ directory
```

### Deploy to Static Host

The built frontend can be deployed to any static hosting service:
- Vercel
- Netlify
- GitHub Pages
- AWS S3 + CloudFront
- Any web server (nginx, Apache)

Configure backend URL:
```typescript
const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8000';
```

## Future Enhancements

🔮 **Recipient Key Manager UI** - Visual interface for managing keys
📈 **Advanced Charts** - Trend analysis over time
🔔 **Notifications** - Alert on critical risk emails
⚙️ **Settings Panel** - Configure quantum timeline, sensitivity rules
📧 **Email Composer** - Integrated email sending interface
🗂️ **Email History** - Search and filter processed emails
