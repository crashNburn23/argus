import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { Eye, EyeOff } from 'lucide-react'
import Button from '../../components/ui/Button'
import { useSettings, useUpdateSettings } from './queries'

const KEY_FIELDS: Array<{ field: string; label: string; statusKey: string }> = [
  { field: 'anthropic_api_key', label: 'Anthropic', statusKey: 'anthropic' },
  { field: 'virustotal_api_key', label: 'VirusTotal', statusKey: 'virustotal' },
  { field: 'shodan_api_key', label: 'Shodan', statusKey: 'shodan' },
  { field: 'recorded_future_api_key', label: 'Recorded Future', statusKey: 'recorded_future' },
  { field: 'otx_api_key', label: 'AlienVault OTX', statusKey: 'otx' },
  { field: 'abuseipdb_api_key', label: 'AbuseIPDB', statusKey: 'abuseipdb' },
  { field: 'misp_api_key', label: 'MISP', statusKey: 'misp' },
]

type FormValues = Record<string, string>

export default function ApiKeysSettings() {
  const { data: settings } = useSettings()
  const update = useUpdateSettings()
  const [visible, setVisible] = useState<Record<string, boolean>>({})
  const [saved, setSaved] = useState(false)

  const { register, handleSubmit, reset, watch } = useForm<FormValues>({
    defaultValues: Object.fromEntries(KEY_FIELDS.map(f => [f.field, ''])),
  })

  const values = watch()
  const hasInput = Object.values(values).some(v => v.trim())

  const onSubmit = handleSubmit(async formValues => {
    const payload: FormValues = {}
    for (const { field } of KEY_FIELDS) {
      if (formValues[field]?.trim()) payload[field] = formValues[field].trim()
    }
    if (Object.keys(payload).length === 0) return
    await update.mutateAsync(payload)
    reset()
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  })

  if (!settings) return null

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-base font-semibold">API Keys</h2>
        <div className="flex items-center gap-3">
          {saved && <span className="text-xs text-success">Saved</span>}
          {update.isError && <span className="text-xs text-danger">Save failed</span>}
          <Button
            size="sm"
            onClick={onSubmit}
            disabled={update.isPending || !hasInput}
          >
            {update.isPending ? 'Saving…' : 'Save keys'}
          </Button>
        </div>
      </div>
      <p className="mb-3 text-xs text-muted-foreground">
        Leave a field blank to keep the existing key. Values are written to{' '}
        <span className="font-mono">.env</span>.
      </p>
      <div className="divide-y divide-border rounded-lg border border-border bg-surface">
        {KEY_FIELDS.map(({ field, label, statusKey }) => {
          const configured = settings.api_keys_configured[statusKey] ?? false
          const isVisible = visible[field] ?? false
          return (
            <div key={field} className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:gap-3">
              <div className="flex items-center justify-between gap-3 sm:w-52 sm:shrink-0 sm:justify-start">
                <span className="text-sm text-muted-foreground sm:w-36">{label}</span>
                <span
                className={`shrink-0 rounded-full px-2 py-0.5 text-xs ${
                  configured ? 'bg-success/20 text-success' : 'bg-muted text-muted-foreground'
                }`}
                >
                  {configured ? 'set' : 'not set'}
                </span>
              </div>
              <div className="flex min-w-0 flex-1 items-center gap-1">
                <input
                  type={isVisible ? 'text' : 'password'}
                  className="h-8 flex-1 rounded border border-border bg-surface-raised px-2 font-mono text-sm text-foreground outline-none transition-colors focus:border-accent focus:ring-1 focus:ring-accent"
                  placeholder={configured ? '••••••••  (leave blank to keep)' : 'Enter API key…'}
                  autoComplete="off"
                  {...register(field)}
                />
                <button
                  type="button"
                  onClick={() => setVisible(v => ({ ...v, [field]: !v[field] }))}
                  className="shrink-0 px-2 py-1 text-xs text-muted-foreground hover:text-foreground"
                  aria-label={isVisible ? 'Hide key' : 'Show key'}
                >
                  {isVisible ? <EyeOff className="size-4" aria-hidden="true" /> : <Eye className="size-4" aria-hidden="true" />}
                </button>
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}
