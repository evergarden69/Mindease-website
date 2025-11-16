// static/js/dashboard.js
document.addEventListener('DOMContentLoaded', () => {
  const toggles = document.querySelectorAll('.task-toggle');
  toggles.forEach(t => {
    t.addEventListener('change', async (e) => {
      const idx = e.target.dataset.index;
      try {
        const resp = await fetch('/toggle_task', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ index: idx })
        });
        const data = await resp.json();
        if (data && data.success) {
          // update UI: mark done class & progress
          const li = e.target.closest('li');
          if (data.done) li.classList.add('done'); else li.classList.remove('done');

          // update progress fill and text
          const fill = document.querySelector('.progress-fill');
          if (fill) {
            fill.style.width = data.progress + '%';
            const label = document.querySelector('.progress-label strong');
            if (label) label.textContent = data.progress + '%';
          }
        } else {
          console.error('Toggle failed', data);
        }
      } catch (err) {
        console.error('Error toggling', err);
      }
    });
  });
});
