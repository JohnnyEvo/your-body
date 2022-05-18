import { writable } from 'svelte-local-storage-store'

export const user = writable('user', { loggedIn: false, accessToken: null, email: null });
