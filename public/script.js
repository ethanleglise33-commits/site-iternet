const API_BASE = '/api';

// ── Chargement des messages ──────────────────────────────────────────────────
async function loadMessages() {
  const container = document.getElementById('messages-container');

  try {
    const res = await fetch(`${API_BASE}/messages`);
    if (!res.ok) throw new Error('Erreur lors du chargement des messages.');
    const messages = await res.json();

    const badge = document.getElementById('message-count');
    badge.textContent = messages.length;
    badge.hidden = false;

    if (messages.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="icon">💬</div>
          <p>Aucun message pour l'instant.<br>Soyez le premier !</p>
        </div>`;
      return;
    }

    container.innerHTML = messages
      .map(
        (msg) => `
      <div class="message-card" data-id="${escapeAttr(msg.id)}">
        <div class="message-content">
          <div class="message-author">${escapeHtml(msg.author)}</div>
          <div class="message-text">${escapeHtml(msg.text)}</div>
          <div class="message-date">${formatDate(msg.created_at)}</div>
        </div>
        <button class="delete-btn" onclick="deleteMessage('${escapeAttr(msg.id)}')" title="Supprimer">🗑️</button>
      </div>`
      )
      .join('');
  } catch (err) {
    container.innerHTML = `<div class="error-msg">❌ ${escapeHtml(err.message)}</div>`;
  }
}

// ── Suppression d'un message ─────────────────────────────────────────────────
async function deleteMessage(id) {
  if (!confirm('Supprimer ce message définitivement ?')) return;

  try {
    const res = await fetch(`${API_BASE}/messages/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) throw new Error('Erreur lors de la suppression.');

    const card = document.querySelector(`[data-id="${CSS.escape(id)}"]`);
    if (card) {
      card.style.transition = 'opacity 0.25s, transform 0.25s';
      card.style.opacity = '0';
      card.style.transform = 'translateX(16px)';
      setTimeout(() => loadMessages(), 280);
    }
  } catch (err) {
    alert(err.message);
  }
}

// ── Envoi du formulaire ──────────────────────────────────────────────────────
document.getElementById('message-form').addEventListener('submit', async (e) => {
  e.preventDefault();

  const text = document.getElementById('message').value;
  const author = document.getElementById('author').value;
  const errorDiv = document.getElementById('form-error');
  const submitBtn = document.getElementById('submit-btn');

  errorDiv.hidden = true;
  submitBtn.disabled = true;
  submitBtn.querySelector('.btn-text').hidden = true;
  submitBtn.querySelector('.btn-loader').hidden = false;

  try {
    const res = await fetch(`${API_BASE}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, author }),
    });

    const data = await res.json();

    if (!res.ok) {
      errorDiv.textContent = data.error || 'Une erreur est survenue.';
      errorDiv.hidden = false;
      return;
    }

    document.getElementById('message').value = '';
    document.getElementById('char-count').textContent = '0';
    loadMessages();
  } catch {
    errorDiv.textContent = 'Impossible de se connecter au serveur.';
    errorDiv.hidden = false;
  } finally {
    submitBtn.disabled = false;
    submitBtn.querySelector('.btn-text').hidden = false;
    submitBtn.querySelector('.btn-loader').hidden = true;
  }
});

// ── Compteur de caractères ───────────────────────────────────────────────────
document.getElementById('message').addEventListener('input', function () {
  document.getElementById('char-count').textContent = this.value.length;
});

// ── Utilitaires ──────────────────────────────────────────────────────────────
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('fr-FR', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

// ── Init ─────────────────────────────────────────────────────────────────────
loadMessages();
