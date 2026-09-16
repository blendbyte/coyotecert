(() => {
  const nav = document.querySelector(".site-nav");
  const toggle = document.querySelector(".nav-toggle");
  const panel = document.getElementById("nav-panel");

  const setOpen = (open) => {
    if (!toggle || !panel) return;
    toggle.setAttribute("aria-expanded", String(open));
    panel.classList.toggle("is-open", open);
    document.body.classList.toggle("nav-open", open);
  };

  toggle?.addEventListener("click", () => {
    setOpen(toggle.getAttribute("aria-expanded") !== "true");
  });

  panel?.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => setOpen(false));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setOpen(false);
  });

  const onScroll = () => {
    nav?.classList.toggle("is-scrolled", window.scrollY > 8);
  };
  onScroll();
  window.addEventListener("scroll", onScroll, { passive: true });

  document.querySelectorAll("[data-copy]").forEach((button) => {
    const original = button.textContent.trim();
    button.addEventListener("click", async () => {
      const value = button.getAttribute("data-copy") || "";
      try {
        await navigator.clipboard.writeText(value);
        button.textContent = "copied. go forth.";
        button.classList.add("is-copied");
        window.setTimeout(() => {
          button.textContent = original;
          button.classList.remove("is-copied");
        }, 1800);
      } catch {
        button.textContent = original;
      }
    });
  });
})();
