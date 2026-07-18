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

// Tauri's ResizeDirection union (not exported by @tauri-apps/api/window).
type ResizeDirection =
  | 'East' | 'North' | 'NorthEast' | 'NorthWest'
  | 'South' | 'SouthEast' | 'SouthWest' | 'West'

const RESIZE_DIRECTIONS: ReadonlySet<string> = new Set<ResizeDirection>([
  'East', 'North', 'NorthEast', 'NorthWest',
  'South', 'SouthEast', 'SouthWest', 'West',
])

async function beginResize(direction: ResizeDirection) {
  try {
    await getCurrentWindow().startResizeDragging(direction)
  } catch {
    // ignore — Tauri may not be available outside the Tauri runtime
  }
}

// Wire up the SE-corner resize grip: mousedown hands off to Tauri so the
// native window manager drives the drag.
const grip = document.querySelector<HTMLElement>('.resize-grip')
if (grip) {
  grip.addEventListener('mousedown', (e) => {
    e.preventDefault()
    void beginResize('SouthEast')
  })
}

// Edge + corner handles: 6px-wide bands on each side + 8px corners.
// These overlay the visible 4px border so the user can grab anywhere on
// the frame, not just exactly on the pixel line.
document.querySelectorAll<HTMLElement>('.edge-handle').forEach((el) => {
  el.addEventListener('mousedown', (e) => {
    e.preventDefault()
    const edge = el.dataset.edge
    if (!edge || !RESIZE_DIRECTIONS.has(edge)) return
    void beginResize(edge as ResizeDirection)
  })
})
