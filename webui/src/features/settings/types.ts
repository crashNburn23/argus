export interface AppSettings {
  model_provider: string
  model: string
  disclosure_mode: string
  log_level: string
  ollama_base_url: string
  ollama_timeout_seconds: number
  misp_url: string
  cases_dir: string
  reports_dir: string
  db_path: string
  model_options: Record<string, string[]>
  api_keys_configured: Record<string, boolean>
}

export interface UpdateSettingsPayload {
  model_provider?: string
  model?: string
  disclosure_mode?: string
  ollama_base_url?: string
  log_level?: string
  anthropic_api_key?: string
  virustotal_api_key?: string
  shodan_api_key?: string
  recorded_future_api_key?: string
  otx_api_key?: string
  abuseipdb_api_key?: string
  misp_api_key?: string
}

export interface Tool {
  name: string
  available: boolean
  reason?: string
}

export interface Agent {
  name: string
  description: string
  tools: string[]
}
