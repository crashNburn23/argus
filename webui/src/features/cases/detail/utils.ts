import type { ObservableInput } from './types'

export function detectObservableType(value: string): string {
  const normalized = value.trim()
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?$/.test(normalized)) return 'ip'
  if (/^[a-fA-F0-9]{64}$/.test(normalized)) return 'sha256'
  if (/^[a-fA-F0-9]{40}$/.test(normalized)) return 'sha1'
  if (/^[a-fA-F0-9]{32}$/.test(normalized)) return 'md5'
  if (/^CVE-\d{4}-\d+$/i.test(normalized)) return 'cve'
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalized)) return 'email'
  if (/^https?:\/\//i.test(normalized)) return 'url'
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$/.test(normalized)) return 'domain'
  return 'unknown'
}

export function parseObservableText(text: string): ObservableInput[] {
  return text
    .split(/[\n,;]+/)
    .map(value => value.trim())
    .filter(Boolean)
    .map(value => ({ value, observable_type: detectObservableType(value) }))
}
