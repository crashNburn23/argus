export const THEME_STORAGE_KEY = 'argus-ui-theme'

export function applyStoredTheme() {
  const theme = localStorage.getItem(THEME_STORAGE_KEY) || 'graphite'
  document.documentElement.dataset.theme = theme
}

export function initializeTheme() {
  applyStoredTheme()

  const onThemeChange = (event: Event) => {
    const nextTheme = (event as CustomEvent<string>).detail
    document.documentElement.dataset.theme = nextTheme || 'graphite'
  }

  window.addEventListener('argus-theme-change', onThemeChange)
}
