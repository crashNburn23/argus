import { test, expect } from '@playwright/test'

async function openFirstCase(page: import('@playwright/test').Page) {
  await page.goto('/cases')
  await page.locator('section[aria-label="Case list"] a').first().click()
}

test.describe('Workspace UX', () => {
  test('chat starter populates the composer', async ({ page }) => {
    await page.goto('/chat')
    await page.getByRole('button', { name: 'Investigate an IOC' }).click()
    await expect(page.getByPlaceholder(/Ask Argus anything/i)).toHaveValue(/Investigate this IOC/)
  })

  test('tools defaults to integration status and exposes source as a secondary view', async ({ page }) => {
    await page.goto('/tools')
    await expect(page.getByText('Registered capabilities')).toBeVisible()
    await page.getByRole('button', { name: 'Source', exact: true }).click()
    await expect(page.getByText('Implementation files')).toBeVisible()
  })

  test('case overview filters observables and graph controls are available', async ({ page }) => {
    await openFirstCase(page)
    await expect(page.getByPlaceholder('Search observable values')).toBeVisible()
    await page.getByRole('tab', { name: 'Graph' }).click()
    await expect(page.getByPlaceholder('Find entity')).toBeVisible({ timeout: 10_000 })
    await expect(page.getByRole('button', { name: 'Fit view' })).toBeVisible()
  })

  test('mobile settings and case navigation do not overflow', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 })
    await page.goto('/settings')
    const settingsOverflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(settingsOverflow).toBeLessThanOrEqual(0)

    await openFirstCase(page)
    await expect(page.getByLabel('Case workspace section')).toBeVisible()
    await expect(page.getByRole('tablist')).toBeHidden()
  })
})
