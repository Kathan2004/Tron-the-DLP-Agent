import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

const applyBootThemeVars = (theme) => {
  const vars = theme === 'dark'
    ? {
      '--bg-color': '#0d1117', '--panel-bg': '#161b22', '--panel-bg-alt': '#1c2128',
      '--text-main': '#c9d1d9', '--text-strong': '#ffffff', '--text-muted': '#8b949e',
      '--border-color': '#30363d', '--table-bg': '#0d1117', '--table-head-bg': '#1c2128',
      '--main-content-bg': 'radial-gradient(circle at top left, #1f2937 0%, transparent 40%), #0d1117',
    }
    : {
      '--bg-color': '#ffffff', '--panel-bg': '#ffffff', '--panel-bg-alt': '#f7f8fb',
      '--text-main': '#1f2937', '--text-strong': '#111827', '--text-muted': '#2d3748',
      '--border-color': '#e4e7ee', '--table-bg': '#ffffff', '--table-head-bg': '#f4f6fa',
      '--main-content-bg': '#ffffff',
    };
  const rootStyle = document.documentElement?.style;
  if (!rootStyle) return;
  Object.entries(vars).forEach(([k, v]) => rootStyle.setProperty(k, v));
};

try {
  const savedTheme = window.localStorage.getItem('siem-theme');
  const theme = (savedTheme === 'light' || savedTheme === 'dark') ? savedTheme : 'light';
  document.documentElement.setAttribute('data-theme', theme);
  document.body?.setAttribute('data-theme', theme);
  applyBootThemeVars(theme);
} catch (_) {
  document.documentElement.setAttribute('data-theme', 'light');
  document.body?.setAttribute('data-theme', 'light');
  applyBootThemeVars('light');
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
