import { test, expect } from '@playwright/test'

// Requires: Argus backend running on :8000 and Vite dev server on :5173
// Run with: npx playwright test

test.describe('Case workflow', () => {
  test('navigates to cases list', async ({ page }) => {
    await page.goto('/cases')
    await expect(page).toHaveTitle(/Argus/)
    await expect(page.getByRole('heading', { name: /Cases/i })).toBeVisible()
  })

  test('creates a new case', async ({ page }) => {
    await page.goto('/cases')

    // Open the create dialog
    await page.getByRole('button', { name: /new case/i }).click()

    // Fill in title
    const titleInput = page.getByRole('textbox', { name: /title/i })
    await expect(titleInput).toBeVisible()
    await titleInput.fill('E2E Test Case')

    // Submit
    await page.getByRole('button', { name: /create/i }).click()

    // Should navigate to the new case or show it in the list
    await expect(page.getByText('E2E Test Case')).toBeVisible({ timeout: 10_000 })
  })

  test('opens a case workspace', async ({ page }) => {
    await page.goto('/cases')

    // Click the first case in the list
    const firstCase = page.getByRole('link').first()
    await firstCase.click()

    // Case workspace should show tabs
    await expect(page.getByRole('tab', { name: /Overview/i })).toBeVisible()
    await expect(page.getByRole('tab', { name: /Notes/i })).toBeVisible()
    await expect(page.getByRole('tab', { name: /References/i })).toBeVisible()
    await expect(page.getByRole('tab', { name: /Reports/i })).toBeVisible()
  })

  test('adds an observable to a case', async ({ page }) => {
    await page.goto('/cases')
    await page.getByRole('link').first().click()

    // Should be on overview tab
    await page.getByRole('tab', { name: /Overview/i }).click()

    // Open the add observables form
    await page.getByRole('button', { name: /add observables/i }).click()
    const textarea = page.getByPlaceholder(/1\.2\.3\.4/i)
    await expect(textarea).toBeVisible()
    await textarea.fill('1.2.3.4\nevil.example.com')

    // Preview should appear
    await expect(page.getByText('ip')).toBeVisible()
    await expect(page.getByText('domain')).toBeVisible()

    // Submit
    await page.getByRole('button', { name: /add 2 observables/i }).click()

    // Form should close and observables appear in list
    await expect(page.getByText('1.2.3.4')).toBeVisible({ timeout: 10_000 })
  })

  test('adds a note to a case', async ({ page }) => {
    await page.goto('/cases')
    await page.getByRole('link').first().click()

    // Navigate to notes tab
    await page.getByRole('tab', { name: /Notes/i }).click()

    // Open the add note form
    await page.getByRole('button', { name: /add note/i }).click()
    const textarea = page.getByPlaceholder(/Analyst note/i)
    await expect(textarea).toBeVisible()
    await textarea.fill('This is a test note from Playwright.')

    // Submit
    await page.getByRole('button', { name: /^add note$/i }).click()

    // Note should appear
    await expect(page.getByText('This is a test note from Playwright.')).toBeVisible({
      timeout: 10_000,
    })
  })

  test('adds a reference to a case', async ({ page }) => {
    await page.goto('/cases')
    await page.getByRole('link').first().click()

    await page.getByRole('tab', { name: /References/i }).click()
    await page.getByRole('button', { name: /add reference/i }).click()

    await page.getByPlaceholder('https://…').fill('https://example.com/report')
    await page.getByPlaceholder('Title or description').fill('Example report')
    await page.getByRole('button', { name: /^add reference$/i }).click()

    await expect(page.getByText('Example report')).toBeVisible({ timeout: 10_000 })
  })

  test('review dialog opens and closes with Escape', async ({ page }) => {
    await page.goto('/cases')
    await page.getByRole('link').first().click()

    // Add a manual observable so Review is enabled
    await page.getByRole('tab', { name: /Overview/i }).click()
    const reviewBtn = page.getByRole('button', { name: /Review/i })

    // Only proceed if review is enabled (has manual items)
    const isDisabled = await reviewBtn.getAttribute('disabled')
    if (isDisabled !== null) {
      // Add an observable first to enable review
      await page.getByRole('button', { name: /add observables/i }).click()
      await page.getByPlaceholder(/1\.2\.3\.4/i).fill('10.0.0.1')
      await page.getByRole('button', { name: /add 1 observable/i }).click()
      await page.waitForTimeout(1000)
    }

    await reviewBtn.click()

    // Dialog should appear
    await expect(page.getByRole('dialog')).toBeVisible()
    await expect(page.getByText('Confirm review scope')).toBeVisible()

    // Focus should be on Cancel button
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeFocused()

    // Escape closes it
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).not.toBeVisible()
  })

  test('tab navigation works with keyboard', async ({ page }) => {
    await page.goto('/cases')
    await page.getByRole('link').first().click()

    // Click the Notes tab
    const notesTab = page.getByRole('tab', { name: /Notes/i })
    await notesTab.click()
    await expect(notesTab).toHaveAttribute('aria-selected', 'true')

    // Click Chat tab
    const chatTab = page.getByRole('tab', { name: 'Chat' })
    await chatTab.click()
    await expect(chatTab).toHaveAttribute('aria-selected', 'true')
    await expect(notesTab).toHaveAttribute('aria-selected', 'false')
  })
})
