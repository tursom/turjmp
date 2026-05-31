const SITE_NAME_KEY = 'branding_site_name'
const DEFAULT_SITE_NAME = 'Turjmp'

export function getStoredSiteName(): string {
  return localStorage.getItem(SITE_NAME_KEY) || DEFAULT_SITE_NAME
}

export function setStoredSiteName(siteName: string): string {
  const normalized = siteName.trim() || DEFAULT_SITE_NAME
  localStorage.setItem(SITE_NAME_KEY, normalized)
  return normalized
}

export function parseSettingString(raw: string): string {
  try {
    const parsed: unknown = JSON.parse(raw)
    return typeof parsed === 'string' ? parsed : String(parsed ?? '')
  } catch {
    return raw
  }
}

export function formatDocumentTitle(pageTitle?: string): string {
  const siteName = getStoredSiteName()
  return pageTitle ? `${pageTitle} - ${siteName}` : siteName
}

export function applyDocumentTitle(pageTitle?: string): void {
  document.title = formatDocumentTitle(pageTitle)
}
