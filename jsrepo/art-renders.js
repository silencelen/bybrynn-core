document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const artId = params.get("art");

  if (!artId) return;

  fetch(`/art/entries.json?cb=${Date.now()}`)
    .then(response => response.json())
    .then(data => {
      const entry = data[artId];
      if (!entry) return;

      document.title = entry.metaTitle;
      document.getElementById("meta-title").textContent = entry.metaTitle;
      document.getElementById("meta-desc").setAttribute("content", entry.description);
      document.getElementById("og-title").setAttribute("content", entry.metaTitle);
      document.getElementById("og-desc").setAttribute("content", entry.description);
      document.getElementById("twitter-title").setAttribute("content", entry.metaTitle);
      document.getElementById("twitter-desc").setAttribute("content", entry.description);
      document.getElementById("meta-onion").setAttribute("content", entry.onion);

      document.getElementById("art-title").textContent = entry.title;
      document.getElementById("art-subheading").textContent = entry.subheading;
      document.getElementById("art-image").src = entry.image;
      document.getElementById("art-description").textContent = entry.description;

      const secContainer = document.getElementById("secondary-image-container");
      if (entry.secondary) {
        const img = document.createElement('img');
        img.src = entry.secondary;
        img.alt = '';
        img.loading = 'lazy';
        secContainer.appendChild(img);
      }

      document.getElementById("prev-link").href = `/art/page.html?art=${entry.prev}`;
      document.getElementById("next-link").href = `/art/page.html?art=${entry.next}`;
    });
});
