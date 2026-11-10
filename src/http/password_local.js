"use strict";
(() => {
  const form = document.getElementById("password-change-form");
  if (!form) return;
  const caption = (button, show) => {
    const icon = document.createElement("span");
    icon.className = "presentation-icon presentation-icon-eye";
    icon.setAttribute("aria-hidden", "true");
    icon.append(document.createElement("i"));
    const label = document.createElement("span");
    label.className = "presentation-label";
    label.textContent = show ? "Hide" : "Show";
    button.replaceChildren(icon, label);
  };
  for (const name of ["current_password", "new_password", "confirmation"]) {
    const input = form.elements.namedItem(name);
    const button = document.getElementById("show-" + name);
    if (!(input instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement)) continue;
    button.hidden = false;
    button.addEventListener("click", () => {
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      caption(button, show);
      button.setAttribute("aria-pressed", show ? "true" : "false");
    });
  }
  window.addEventListener("pageshow", () => {
    for (const name of ["current_password", "new_password", "confirmation", "totp_code"]) {
      const input = form.elements.namedItem(name);
      if (input instanceof HTMLInputElement) {
        input.value = "";
        if (name !== "totp_code") input.type = "password";
      }
      const button = document.getElementById("show-" + name);
      if (button) {
        caption(button, false);
        button.setAttribute("aria-pressed", "false");
      }
    }
  });
})();
