document.addEventListener("DOMContentLoaded", () => {
  const menuToggle = document.getElementById("menu-toggle");
  const navMenu = document.getElementById("nav-menu");
  const navOverlay = document.getElementById("nav-overlay");

  if (menuToggle && navMenu && navOverlay) {
    menuToggle.addEventListener("click", (e) => {
      e.stopPropagation();
      navMenu.classList.toggle("active");
      navOverlay.classList.toggle("active");
    });

    // Cierra menú al hacer clic en overlay o en un enlace del menú
    const closeMenu = () => {
      navMenu.classList.remove("active");
      navOverlay.classList.remove("active");
    };

    navOverlay.addEventListener("click", closeMenu);
    navMenu.querySelectorAll("a").forEach(link => {
      link.addEventListener("click", closeMenu);
    });
  }
});
