(() => {
  "use strict";
  const normalizePath = (pathname) => {
    let path = String(pathname || "/").toLowerCase();
    path = path.replace(/\/index\.html$/i, "");
    path = path.replace(/\.html$/i, "");
    path = path.replace(/\/+$/, "") || "/";
    return path;
  };
  const currentPath = normalizePath(window.location.pathname);
  const allNavLinks = Array.from(document.querySelectorAll("nav a[href]"));
  const primaryLinks = Array.from(document.querySelectorAll("nav .nav-links a[href]"));
  const clearCurrentState = () => {
    allNavLinks.forEach((link) => {
      link.classList.remove("is-current-page");
      link.removeAttribute("aria-current");
    });
    document.querySelectorAll("nav .has-dropdown.is-active-parent").forEach((item) => item.classList.remove("is-active-parent"));
  };
  const markCurrent = (link) => {
    link.classList.add("is-current-page");
    link.setAttribute("aria-current", "page");
    const parentDropdown = link.closest(".dropdown")?.closest(".has-dropdown");
    if (parentDropdown) parentDropdown.classList.add("is-active-parent");
  };
  const findPathMatches = (links) => links.filter((link) => {
    const rawHref = (link.getAttribute("href") || "").trim();
    if (!rawHref || rawHref === "#" || rawHref.startsWith("#")) return false;
    try {
      const url = new URL(rawHref, window.location.href);
      if (url.origin !== window.location.origin) return false;
      // The Solutions parent can share a URL with Individual Wellness. Mark the child and style the parent separately.
      if (link.closest(".has-dropdown") && !link.closest(".dropdown")) return false;
      return normalizePath(url.pathname) === currentPath;
    } catch (_) { return false; }
  });
  clearCurrentState();
  const primaryMatches = findPathMatches(primaryLinks);
  if (primaryMatches.length) {
    // Only highlight one canonical nav link if aliases point to the same page.
    // This prevents both “Wellness Intelligence” and “Insights” being highlighted.
    markCurrent(primaryMatches[0]);
  } else if (currentPath === "/") {
    const homeLink = primaryLinks.find((link) => {
      const label = (link.textContent || "").trim().toLowerCase();
      const href = (link.getAttribute("href") || "").trim();
      return label === "home" && (href === "#home" || normalizePath(new URL(href, window.location.href).pathname) === "/");
    });
    if (homeLink) markCurrent(homeLink);
  } else {
    const actionMatches = findPathMatches(Array.from(document.querySelectorAll("nav .nav-actions a[href], nav a.nav-link-plain[href]")));
    actionMatches.forEach(markCurrent);
  }
  document.querySelectorAll("nav .dropdown a.is-current-page").forEach((link) => {
    const parent = link.closest(".dropdown")?.closest(".has-dropdown");
    if (parent) parent.classList.add("is-active-parent");
  });
  const openDetailsForHash = () => {
    if (!window.location.hash) return;
    let target;
    try { target = document.getElementById(decodeURIComponent(window.location.hash.slice(1))); }
    catch (_) { target = document.getElementById(window.location.hash.slice(1)); }
    if (!target) return;
    const enclosingDetails = target.closest("details");
    if (enclosingDetails) enclosingDetails.open = true;
  };
  openDetailsForHash();
  window.addEventListener("hashchange", openDetailsForHash);
  document.addEventListener("click", (event) => {
    const link = event.target.closest("a[href]");
    if (!link) return;
    let url;
    try { url = new URL(link.href, window.location.href); } catch (_) { return; }
    if (url.origin !== window.location.origin || !url.hash) return;
    const target = document.getElementById(decodeURIComponent(url.hash.slice(1)));
    if (!target) return;
    const enclosingDetails = target.closest("details");
    if (enclosingDetails) enclosingDetails.open = true;
  });
})();
