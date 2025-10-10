// server.js
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

function quickHeuristic(urlStr) {
  const reasons = [];
  try {
    const u = new URL(urlStr);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)) reasons.push('IP address used in URL');
    const low = urlStr.toLowerCase();
    ['login','secure','update','verify','account','bank','confirm'].forEach(tok => {
      if (low.includes(tok)) reasons.push(`Contains "${tok}"`);
    });
    if (u.hostname.includes('xn--')) reasons.push('Punycode (possible homograph)');
    if (urlStr.length > 80) reasons.push('URL length > 80');
    if ((u.hostname.split('.').length) > 4) reasons.push('Many subdomains');
  } catch (e) {
    reasons.push('Malformed URL');
  }
  return reasons;
}

app.get('/api/check', (req, res) => {
  const q = req.query.url;
  if (!q) return res.status(400).json({ error: 'missing url param' });

  const reasons = quickHeuristic(q);
  const verdict = reasons.length === 0 ? 'safe' : (reasons.length <= 2 ? 'suspicious' : 'dangerous');
  const confidence = verdict === 'safe' ? 0.95 : (verdict === 'suspicious' ? 0.65 : 0.4);

  res.json({ url: q, verdict, confidence, reasons });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));
