import PageHeader from '../components/PageHeader'
import ErrorState from '../components/ErrorState'
import LoadingState from '../components/LoadingState'
import GeneralSettings from '../features/settings/GeneralSettings'
import AppearanceSettings from '../features/settings/AppearanceSettings'
import ApiKeysSettings from '../features/settings/ApiKeysSettings'
import { useAgents, useSettings, useTools } from '../features/settings/queries'

export default function Settings() {
  const { isLoading, isError, refetch } = useSettings()
  const { data: tools = [] } = useTools()
  const { data: agents = [] } = useAgents()

  if (isLoading) return <LoadingState label="Loading settings" />
  if (isError) return <ErrorState message="Failed to load settings" onRetry={refetch} />

  return (
    <div className="h-full overflow-y-auto">
      <PageHeader title="Settings" />
      <div className="mx-auto max-w-3xl space-y-8 p-4 sm:p-6">
        <GeneralSettings />
        <AppearanceSettings />
        <ApiKeysSettings />

        {/* Tool availability */}
        <section>
          <h2 className="mb-4 text-base font-semibold">Tools</h2>
          <div className="divide-y divide-border rounded-lg border border-border bg-surface">
            {tools.length === 0 && (
              <p className="px-4 py-3 text-sm text-muted-foreground">No tools registered.</p>
            )}
            {tools.map(tool => (
              <div key={tool.name} className="flex items-center gap-3 px-4 py-3">
                <span className="w-48 shrink-0 font-mono text-sm text-foreground">{tool.name}</span>
                <span
                  className={`shrink-0 rounded-full px-2 py-0.5 text-xs ${
                    tool.available ? 'bg-success/20 text-success' : 'bg-muted text-muted-foreground'
                  }`}
                >
                  {tool.available ? 'available' : 'unavailable'}
                </span>
                {tool.reason && (
                  <span className="text-xs text-muted-foreground">{tool.reason}</span>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* Agent registry */}
        <section>
          <h2 className="mb-4 text-base font-semibold">Agents</h2>
          <div className="space-y-2">
            {agents.map(agent => (
              <div key={agent.name} className="rounded-lg border border-border bg-surface p-4">
                <div className="mb-1 font-medium capitalize text-foreground">{agent.name}</div>
                <div className="mb-2 text-xs text-muted-foreground">{agent.description}</div>
                {agent.tools.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {agent.tools.map(t => (
                      <span
                        key={t}
                        className="rounded bg-surface-raised px-2 py-0.5 font-mono text-xs text-muted-foreground"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  )
}
