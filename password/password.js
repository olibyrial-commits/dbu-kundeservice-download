import { SUPABASE_URL, SUPABASE_ANON_KEY } from './config.js'

/** Recovery secrets stay in memory and are never sent to GitHub or persisted in browser storage. */
export function recoveryParameters(href) {
  const url = new URL(href)
  const params = url.hash ? new URLSearchParams(url.hash.slice(1)) : url.searchParams
  if (params.has('error') || params.has('error_code')) throw new Error('Linket er brugt eller udløbet. Bed om en ny mail fra appen.')
  const type = params.get('type')
  if (type && !['recovery', 'invite'].includes(type)) throw new Error('Dette link kan ikke bruges til at vælge en adgangskode.')
  const accessToken = params.get('access_token')
  const refreshToken = params.get('refresh_token')
  const tokenHash = params.get('token_hash')
  if (!accessToken && !refreshToken && !tokenHash) throw new Error('Åbn linket fra din nulstillingsmail, eller få en ny kode fra din administrator.')
  return { accessToken, refreshToken, tokenHash, type: type || 'recovery' }
}

export async function authRequest(path, { method = 'GET', token, body } = {}, fetcher = fetch) {
  const response = await fetcher(SUPABASE_URL + path, { method, headers: { apikey: SUPABASE_ANON_KEY, authorization: `Bearer ${token || SUPABASE_ANON_KEY}`, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, credentials: 'omit', referrerPolicy: 'no-referrer' })
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    if (response.status === 429) throw new Error('For mange forsøg. Vent et minut og prøv igen.')
    if (data.code === 'weak_password' || data.error_code === 'weak_password') throw new Error('Adgangskoden er for svag. Brug mindst 8 tegn og prøv igen.')
    throw new Error('Linket er ugyldigt eller udløbet. Bed om en ny nulstillingsmail fra appen.')
  }
  return data
}

export async function recoverySession(params, fetcher = fetch) {
  // Refresh first so an expired access token from a delayed email still works.
  const session = params.refreshToken
    ? await authRequest('/auth/v1/token?grant_type=refresh_token', { method: 'POST', body: { refresh_token: params.refreshToken } }, fetcher)
    : params.tokenHash
      ? await authRequest('/auth/v1/verify', { method: 'POST', body: { token_hash: params.tokenHash, type: params.type } }, fetcher)
      : { access_token: params.accessToken }
  const user = await authRequest('/auth/v1/user', { token: session.access_token }, fetcher)
  if (!session.access_token || !user.id || !user.email) throw new Error('Login-serveren gav et ufuldstændigt svar.')
  const profiles = await authRequest(`/rest/v1/profiles?id=eq.${encodeURIComponent(user.id)}&select=active`, { token: session.access_token }, fetcher)
  if (!profiles[0]?.active) throw new Error('Din bruger er ikke aktiveret. Bed administratoren om at aktivere den i DBU Kundeservice.')
  return { token: session.access_token, email: user.email }
}

if (typeof document !== 'undefined') {
  const status = document.querySelector('#status')
  const form = document.querySelector('#password-form')
  const error = document.querySelector('#error')
  const button = document.querySelector('#save')
  let session
  let parameters
  try { parameters = recoveryParameters(location.href) } catch (e) { status.textContent = e.message }
  // Remove tokens before any later navigation or interaction, even on invalid links.
  history.replaceState(null, '', location.pathname)
  if (parameters) recoverySession(parameters).then((s) => {
    session = s
    status.textContent = 'Linket er bekræftet. Vælg en adgangskode på mindst 8 tegn.'
    document.querySelector('#account').textContent = s.email
    form.hidden = false
  }).catch((e) => { status.textContent = e.message })
  form.addEventListener('submit', async (event) => {
    event.preventDefault()
    if (!session || button.disabled) return
    error.textContent = ''
    const password = document.querySelector('#password').value
    if (password.length < 8 || password !== document.querySelector('#repeat').value) { error.textContent = 'Brug mindst 8 tegn og skriv den samme adgangskode i begge felter.'; return }
    button.disabled = true
    try {
      await authRequest('/auth/v1/user', { method: 'PUT', token: session.token, body: { password } })
      const token = session.token; session = null
      form.reset(); form.hidden = true
      status.textContent = 'Din adgangskode er gemt. Åbn DBU Kundeservice og log ind med din e-mail og den nye adgangskode.'
      // Finish this browser recovery session without signing out the user's other devices.
      void authRequest('/auth/v1/logout?scope=local', { method: 'POST', token }).catch(() => undefined)
    } catch (e) { error.textContent = e.message } finally { button.disabled = false }
  })
}
