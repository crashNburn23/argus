import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import Button from '../../components/ui/Button'
import Select from '../../components/ui/Select'
import Input from '../../components/ui/Input'
import { useSettings, useUpdateSettings } from './queries'
import type { AppSettings } from './types'

const ANTHROPIC_MODELS = [
  'claude-sonnet-4-6',
  'claude-opus-4-8',
  'claude-haiku-4-5-20251001',
]

const LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
const DISCLOSURE_MODES = ['unrestricted', 'confirm-external', 'local-only']

interface FormValues {
  model_provider: string
  model: string
  disclosure_mode: string
  log_level: string
  ollama_base_url: string
}

function modelOptions(settings: AppSettings, provider: string): string[] {
  return settings.model_options?.[provider] ?? (provider === 'anthropic' ? ANTHROPIC_MODELS : [])
}

export default function GeneralSettings() {
  const { data: settings } = useSettings()
  const update = useUpdateSettings()
  const [editing, setEditing] = useState(false)
  const [saved, setSaved] = useState(false)

  const { register, handleSubmit, watch, reset, setValue } = useForm<FormValues>()
  const provider = watch('model_provider')
  const models = settings ? modelOptions(settings, provider ?? settings.model_provider) : []

  useEffect(() => {
    if (settings && !editing) {
      reset({
        model_provider: settings.model_provider,
        model: settings.model,
        disclosure_mode: settings.disclosure_mode,
        log_level: settings.log_level,
        ollama_base_url: settings.ollama_base_url,
      })
    }
  }, [settings, editing, reset])

  // Reset model when provider changes
  useEffect(() => {
    if (editing && settings) {
      const opts = modelOptions(settings, provider)
      setValue('model', opts[0] ?? '')
    }
  }, [provider, editing, settings, setValue])

  const onSubmit = handleSubmit(async values => {
    await update.mutateAsync(values)
    setEditing(false)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  })

  if (!settings) return null

  return (
    <section>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-base font-semibold">General</h2>
        <div className="flex items-center gap-3">
          {saved && <span className="text-xs text-success">Saved</span>}
          {update.isError && <span className="text-xs text-danger">Save failed</span>}
          {editing ? (
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={onSubmit}
                disabled={update.isPending}
              >
                {update.isPending ? 'Saving…' : 'Save'}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => { setEditing(false); reset() }}
              >
                Cancel
              </Button>
            </div>
          ) : (
            <Button size="sm" variant="secondary" onClick={() => setEditing(true)}>
              Edit
            </Button>
          )}
        </div>
      </div>

      <div className="divide-y divide-border rounded-lg border border-border bg-surface">
        <Row label="Model Provider">
          {editing ? (
            <Select {...register('model_provider')} className="flex-1">
              <option value="anthropic">anthropic</option>
              <option value="ollama">ollama</option>
            </Select>
          ) : (
            <Mono>{settings.model_provider}</Mono>
          )}
        </Row>

        <Row label="Model">
          {editing ? (
            <Select {...register('model')} className="flex-1" disabled={models.length === 0}>
              {models.length > 0
                ? models.map(m => <option key={m} value={m}>{m}</option>)
                : <option value="">No models found</option>
              }
            </Select>
          ) : (
            <Mono>{settings.model || '—'}</Mono>
          )}
        </Row>

        <Row label="Disclosure Mode">
          {editing ? (
            <Select {...register('disclosure_mode')} className="flex-1">
              {DISCLOSURE_MODES.map(m => <option key={m} value={m}>{m}</option>)}
            </Select>
          ) : (
            <Mono>{settings.disclosure_mode}</Mono>
          )}
        </Row>

        <Row label="Log Level">
          {editing ? (
            <Select {...register('log_level')} className="flex-1">
              {LOG_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </Select>
          ) : (
            <Mono>{settings.log_level}</Mono>
          )}
        </Row>

        {(editing ? provider === 'ollama' : settings.model_provider === 'ollama') && (
          <Row label="Ollama URL">
            {editing ? (
              <Input {...register('ollama_base_url')} className="flex-1" />
            ) : (
              <Mono>{settings.ollama_base_url || '—'}</Mono>
            )}
          </Row>
        )}

        {([
          ['Cases Dir', settings.cases_dir],
          ['Reports Dir', settings.reports_dir],
          ['DB Path', settings.db_path],
        ] as const).map(([label, val]) => (
          <Row key={label} label={label}>
            <span className="truncate font-mono text-sm text-muted-foreground">{val}</span>
          </Row>
        ))}
      </div>
    </section>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-4 px-4 py-3">
      <span className="w-40 shrink-0 text-sm text-muted-foreground">{label}</span>
      {children}
    </div>
  )
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-sm text-foreground">{children}</span>
}
