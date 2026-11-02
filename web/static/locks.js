async function refreshLocks() {
  try {
    const response = await fetch('/api/vm-locks', {cache: 'no-store'});
    if (!response.ok) return;
    const locks = await response.json();
    document.querySelectorAll('[data-vm-id]').forEach(row => {
      const state = locks[row.dataset.vmId];
      const locked = !state || state.disabled;
      row.querySelector('[data-lock-status]').textContent = state ? state.text : 'Access unavailable';
      row.querySelectorAll('button, input[type=checkbox]').forEach(control => control.disabled = locked);
    });
    const banner = document.querySelector('[data-backend-banner]');
    if (banner) banner.hidden = !Object.values(locks).some(state => state.backend_unavailable);
  } catch (_) { /* Server-side locks remain authoritative during connectivity loss. */ }
}
setInterval(refreshLocks, 5000);
refreshLocks();
