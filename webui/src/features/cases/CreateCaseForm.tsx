import { zodResolver } from '@hookform/resolvers/zod'
import { LoaderCircle } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { ApiError } from '../../api/client'
import Button from '../../components/ui/Button'
import Input from '../../components/ui/Input'
import Select from '../../components/ui/Select'
import Textarea from '../../components/ui/Textarea'
import { useCreateCase } from './queries'

const createCaseSchema = z.object({
  title: z.string().trim().min(1, 'Enter a case title').max(200, 'Keep the title under 200 characters'),
  description: z.string().trim().max(4_000, 'Keep the description under 4,000 characters'),
  classification: z.string().min(1),
})

type CreateCaseValues = z.infer<typeof createCaseSchema>

export default function CreateCaseForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const createCase = useCreateCase()
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<CreateCaseValues>({
    resolver: zodResolver(createCaseSchema),
    defaultValues: { title: '', description: '', classification: 'TLP:AMBER' },
  })

  const submit = handleSubmit(async values => {
    await createCase.mutateAsync(values)
    onCreated()
  })

  const errorMessage = createCase.error instanceof ApiError
    ? createCase.error.message
    : createCase.error
      ? 'The case could not be created.'
      : ''

  return (
    <form onSubmit={submit} className="rounded-xl border border-border bg-surface p-4 shadow-sm sm:p-5">
      <div className="mb-4">
        <h2 className="text-sm font-semibold text-foreground">Create case</h2>
        <p className="mt-1 text-xs text-muted-foreground">Start an investigation workspace. You can add observables and evidence after creation.</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_11rem]">
        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-foreground">Title</span>
          <Input autoFocus placeholder="Investigation title" aria-invalid={Boolean(errors.title)} {...register('title')} />
          {errors.title && <span className="mt-1 block text-xs text-danger">{errors.title.message}</span>}
        </label>
        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-foreground">Classification</span>
          <Select {...register('classification')}>
            <option value="TLP:CLEAR">TLP:CLEAR</option>
            <option value="TLP:GREEN">TLP:GREEN</option>
            <option value="TLP:AMBER">TLP:AMBER</option>
            <option value="TLP:AMBER+STRICT">TLP:AMBER+STRICT</option>
            <option value="TLP:RED">TLP:RED</option>
          </Select>
        </label>
      </div>

      <label className="mt-4 block">
        <span className="mb-1.5 block text-xs font-medium text-foreground">Description <span className="font-normal text-muted-foreground">(optional)</span></span>
        <Textarea rows={3} placeholder="What triggered this investigation?" aria-invalid={Boolean(errors.description)} {...register('description')} />
        {errors.description && <span className="mt-1 block text-xs text-danger">{errors.description.message}</span>}
      </label>

      {errorMessage && <p role="alert" className="mt-3 text-sm text-danger">{errorMessage}</p>}

      <div className="mt-4 flex items-center gap-2">
        <Button type="submit" disabled={createCase.isPending}>
          {createCase.isPending && <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />}
          Create case
        </Button>
        <Button variant="ghost" onClick={onCancel} disabled={createCase.isPending}>Cancel</Button>
      </div>
    </form>
  )
}
