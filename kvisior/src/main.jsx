import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { AppProvider } from './context/AppContext'
import { PermissionsProvider } from './context/PermissionsContext'
import { App } from './App'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <AppProvider>
      <PermissionsProvider>
        <App />
      </PermissionsProvider>
    </AppProvider>
  </StrictMode>
)
