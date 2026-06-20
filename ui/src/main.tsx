import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { getCurrentWindow } from '@tauri-apps/api/window'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)

// Wire up the SE-corner resize grip: mousedown hands off to Tauri so the
// native window manager drives the drag.
const grip = document.querySelector<HTMLElement>('.resize-grip')
if (grip) {
  grip.addEventListener('mousedown', async (e) => {
    e.preventDefault()
    try {
      // Tauri v2 typings don't always expose startResizing; cast to any.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (getCurrentWindow() as any).startResizing('SouthEast')
    } catch {
      // ignore — Tauri may not be available outside the Tauri runtime
    }
  })
}

// Edge + corner handles: 6px-wide bands on each side + 8px corners.
// These overlay the visible 4px border so the user can grab anywhere on
// the frame, not just exactly on the pixel line.
document.querySelectorAll<HTMLElement>('.edge-handle').forEach((el) => {
  el.addEventListener('mousedown', async (e) => {
    e.preventDefault()
    const edge = el.dataset.edge
    if (!edge) return
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (getCurrentWindow() as any).startResizing(edge)
    } catch {
      // ignore
    }
  })
})
