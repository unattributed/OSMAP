// Compose-only enhancement. Native form submission remains authoritative.
(() => {
  "use strict";
  const form = document.getElementById("compose-form");
  if (!form || form.dataset.enhancement !== "local-v1") return;
  const status = document.getElementById("compose-save-status");
  const save = document.getElementById("compose-save");
  const upload = document.getElementById("compose-attachment");
  const imageUpload = document.getElementById("compose-image");
  const heading = document.getElementById("compose-attachments-heading");
  if (!status || !save || !upload || !heading) return;

  let initialState = form.dataset.saveState;
  let blocked = initialState === "unconfirmed";
  let inheritedChanges = initialState === "unsaved" || blocked;
  const watched = [...form.querySelectorAll(
    'input[name="to"], input[name="cc"], input[name="bcc"], input[name="subject"], textarea[name="body"], select[name="body_format"], input[name="pgp_sign"], input[name="pgp_encrypt"], input[name="pgp_self"], input[name^="remove_saved_attachment_"], input[name^="include_original_attachment_"]'
  )];
  const value = (field) => field.type === "checkbox" ? field.checked : field.value;
  const baseline = watched.map(value);
  const previewBaseline = [...baseline];
  const previewInheritedChanges = inheritedChanges;
  let submitting = false;
  let autoFlight = false;
  let pending = [...upload.files];
  const pendingImages = () => imageUpload ? [...imageUpload.files] : [];
  let beforeUnloadAttached = false;
  const dirty = () => inheritedChanges || upload.files.length > 0 || pendingImages().length > 0 ||
    watched.some((field, index) => value(field) !== baseline[index]);
  const warnBeforeLeaving = (event) => {
    if (!submitting && (dirty() || autoFlight)) {
      event.preventDefault();
      event.returnValue = "";
    }
  };
  const updateState = () => {
    const changed = dirty();
    const message = blocked ? "Save not confirmed — compare with the stored version." :
      changed ? "Unsaved changes — Save Draft to keep this version." :
      initialState === "saved" ? "Saved draft." : "Not saved yet.";
    if (status.textContent !== message) status.textContent = message;
    status.dataset.state = blocked ? "unconfirmed" : changed ? "unsaved" : initialState;
    const previewChanged = previewInheritedChanges || upload.files.length > 0 || pendingImages().length > 0 ||
      watched.some((field, index) => value(field) !== previewBaseline[index]);
    form.querySelectorAll(".compose-preview").forEach((panel) => {
      panel.dataset.stale = String(previewChanged);
      let hint = panel.querySelector(".compose-stale-preview");
      if (!hint) {
        hint = document.createElement("p");
        hint.className = "compose-stale-preview";
        hint.textContent = "This preview or check has not been refreshed. Save and preview or check again after editing.";
        panel.append(hint);
      }
      hint.hidden = !previewChanged;
    });
    if ((changed || autoFlight) && !beforeUnloadAttached) {
      window.addEventListener("beforeunload", warnBeforeLeaving);
      beforeUnloadAttached = true;
    } else if (!changed && !autoFlight && beforeUnloadAttached) {
      window.removeEventListener("beforeunload", warnBeforeLeaving);
      beforeUnloadAttached = false;
    }
  };
  form.addEventListener("input", updateState);
  form.addEventListener("change", updateState);
  window.addEventListener("pageshow", () => { submitting = false; updateState(); });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey &&
        event.key.toLowerCase() === "s") {
      event.preventDefault();
      if (!save.disabled) {
        if (typeof form.requestSubmit === "function") form.requestSubmit(save);
        else save.click();
      }
      else updateState();
    }
  });
  form.addEventListener("submit", (event) => {
    const start = form.querySelector('input[name="format_start"]');
    const end = form.querySelector('input[name="format_end"]');
    const body = document.getElementById("compose-body");
    if (start && end) {
      start.value = end.value = "";
      const action = event.submitter;
      const selectedActions = ["format-bold", "format-italic", "format-underline",
        "format-bullets", "format-numbers", "format-link"];
      // Browser selection offsets are UTF-16 code units. The server owns the
      // transformation; an empty selection means whole body, emoji appends.
      if (body && action && action.name === "compose_action" &&
          selectedActions.includes(action.value) && body.selectionEnd > body.selectionStart) {
        start.value = String(body.selectionStart);
        end.value = String(body.selectionEnd);
      }
    }
    if (!event.defaultPrevented) submitting = true;
  });
  updateState();

  // Automatic saving is opt-in and never uses a returned document as authority.
  const autoStatus = document.getElementById("compose-auto-status");
  let autoEnabled = false, autoInterval = 30000, autoPaused = blocked;
  let autoTimer;
  const authorButtons = () => [...document.querySelectorAll('button[type="submit"]')]
    .filter((button) => button.form === form || button.form?.id === "compose-discard-form");
  const lockedButtons = new Map();
  const lockAuthoring = () => authorButtons().forEach((button) => {
    if (!lockedButtons.has(button)) lockedButtons.set(button, button.disabled);
    button.disabled = true;
  });
  const unlockAuthoring = () => { lockedButtons.forEach((disabled, button) => { button.disabled = disabled; }); lockedButtons.clear(); };
  const announceAuto = (text) => { if (autoStatus) autoStatus.textContent = text; };
  const pauseAuto = () => {
    autoPaused = true; blocked = true; submitting = false; lockAuthoring(); updateState();
    announceAuto("Auto-save paused: the server outcome is not confirmed. Keep this tab open and compare the stored version; no automatic retry will occur. ");
    const link = document.createElement("a");
    const id = form.elements.namedItem("draft_id")?.value;
    const intent = form.elements.namedItem("send_intent")?.value;
    link.href = id ? `/draft?id=${encodeURIComponent(id)}` : `/compose?receipt=${encodeURIComponent(intent || "")}`;
    link.target = "_blank"; link.rel = "noopener noreferrer";
    link.textContent = "Review saved state in a new tab"; autoStatus?.append(link);
  };
  document.addEventListener("submit", (event) => {
    if (autoFlight || (autoPaused && (event.target === form || event.target.id === "compose-discard-form"))) {
      event.preventDefault(); event.stopImmediatePropagation(); submitting = false;
      if (autoFlight) announceAuto("Auto-save in progress. Wait before saving, sending, formatting or leaving this page.");
    } else if (event.target === form || event.target.id === "compose-discard-form") { clearTimeout(autoTimer); submitting = true; announceAuto("Auto-save stopped for the manual action. If it is cancelled, use Save Draft or reload to resume auto-save."); }
  }, true);
  document.addEventListener("click", (event) => {
    if (autoFlight && event.target.closest("a[href]")) {
      event.preventDefault(); event.stopImmediatePropagation();
      announceAuto("Auto-save in progress. Wait before leaving this page.");
    }
  }, true);
  const hidden = (name, value) => {
    let field = form.elements.namedItem(name);
    if (!field) { field = document.createElement("input"); field.type = "hidden"; field.name = name; form.append(field); }
    field.value = String(value);
  };
  const jsonReply = async (response) => {
    if (response.status !== 200 || response.redirected || response.headers.get("content-type") !== "application/json") throw new Error("unconfirmed");
    const reader = response.body.getReader(); let text = "", bytes = 0; const decoder = new TextDecoder();
    for (;;) { const { done, value } = await reader.read(); if (done) break; bytes += value.length;
      if (bytes > 4096) { await reader.cancel(); throw new Error("unconfirmed"); } text += decoder.decode(value, { stream: true }); }
    text += decoder.decode(); return JSON.parse(text);
  };
  const saveAutomatically = async () => {
    if (!autoEnabled || autoPaused || autoFlight || submitting || document.visibilityState !== "visible" || !dirty()) return;
    if (upload.files.length || pendingImages().length ||
        form.querySelector('input[name^="remove_saved_attachment_"]:checked, input[name^="include_original_attachment_"]:checked, input[name="source_mailbox"]') ||
        form.querySelector('select[name="contact_id"]')?.value) {
      announceAuto("Auto-save waiting: use Save Draft for pending files, source attachments or a selected contact."); return;
    }
    const savedValues = watched.map(value);
    const expectedId = form.elements.namedItem("draft_id")?.value || "";
    const previousRevision = form.elements.namedItem("draft_revision")?.value || "0";
    const fields = new URLSearchParams();
    const allowed = ["csrf_token", "send_intent", "from", "to", "cc", "bcc", "subject", "body", "body_format", "pgp_sign", "pgp_encrypt", "pgp_self", "pgp_binding_revision", "draft_id", "draft_revision", "reply_mailbox", "reply_uid", "reply_mailbox_guid", "reply_message_guid"];
    for (const name of allowed) {
      const field = form.elements.namedItem(name);
      if (field && (field.type !== "checkbox" || field.checked)) fields.set(name, field.value);
    }
    let controller;
    try { controller = new AbortController(); } catch {
      autoEnabled = false; announceAuto("Auto-save is unsupported in this browser. Use Save Draft to keep changes."); return;
    }
    autoFlight = true; lockAuthoring(); announceAuto("Saving draft automatically…");
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const result = await jsonReply(await fetch("/drafts/autosave", { method: "POST", body: fields,
        credentials: "same-origin", mode: "same-origin", redirect: "error", cache: "no-store", signal: controller.signal }));
      if (result.version !== 1 || result.state !== "saved" || typeof result.draft_id !== "string" ||
          !/^[a-f0-9]{32}$/.test(result.draft_id) || (expectedId && expectedId !== result.draft_id) ||
          !Number.isSafeInteger(result.revision) || result.revision !== Number(previousRevision) + 1 ||
          typeof result.send_intent !== "string" || !/^[1-9][0-9]*\.[a-f0-9]{32}$/.test(result.send_intent) ||
          typeof result.display_name !== "string" || !(result.reply_to === null || typeof result.reply_to === "string")) throw new Error("unconfirmed");
      hidden("draft_id", result.draft_id); hidden("draft_revision", result.revision); hidden("send_intent", result.send_intent);
      for (const name of allowed.filter((name) => name.startsWith("reply_"))) form.elements.namedItem(name)?.remove();
      history.replaceState(null, "", `/draft?id=${encodeURIComponent(result.draft_id)}`);
      const draftHeading = form.querySelector(".compose-card-header h2"); if (draftHeading) draftHeading.textContent = "Saved Draft";
      baseline.splice(0, baseline.length, ...savedValues); inheritedChanges = false; initialState = "saved";
      const account = form.elements.namedItem("from").value;
      const sender = form.querySelector(".compose-sender-chip");
      if (sender) sender.textContent = result.display_name ? `${result.display_name} <${account}>` : account;
      const policy = document.getElementById("sender-policy");
      if (policy) policy.textContent = `This draft has captured its sender identity. Reply-to: ${result.reply_to || account}. Saved drafts keep this identity after profile changes.`;
      const discard = document.getElementById("compose-discard-form");
      if (discard) { const selected = discard.querySelector('input[name^="selected_"]'); if (selected) selected.value = String(result.revision); }
      else {
        const unsaved = form.querySelector('a[data-confirm-discard="true"]');
        if (unsaved) { unsaved.removeAttribute("data-confirm-discard"); unsaved.href = `/draft?id=${encodeURIComponent(result.draft_id)}`; unsaved.target = "_blank"; unsaved.rel = "noopener noreferrer"; unsaved.textContent = "Open saved draft to review discard"; unsaved.previousElementSibling.textContent = "This message is now saved. Review its stored version before discarding it."; }
      }
      unlockAuthoring(); updateState();
      announceAuto(dirty() ? "Earlier edits saved. Newer changes remain unsaved." : "Auto-save confirmed.");
    } catch { pauseAuto(); }
    finally { clearTimeout(timeout); autoFlight = false; updateState(); }
  };
  const scheduleAuto = () => { autoTimer = setTimeout(async () => { await saveAutomatically(); if (!autoPaused && !submitting) scheduleAuto(); }, autoInterval); };
  const autoSupported = typeof fetch === "function" && typeof URLSearchParams === "function" &&
    typeof AbortController === "function" && typeof TextDecoder === "function" &&
    typeof ReadableStream === "function" && typeof Response === "function" &&
    "body" in Response.prototype && "getReader" in ReadableStream.prototype;
  if (autoStatus && !autoSupported) announceAuto("Auto-save is unsupported in this browser. Use Save Draft to keep changes.");
  if (autoStatus && !blocked && autoSupported) {
    fetch("/drafts/autosave/config", { credentials: "same-origin", mode: "same-origin", redirect: "error", cache: "no-store" })
      .then(jsonReply).then((config) => {
        if (config.version !== 1 || typeof config.enabled !== "boolean" || ![30,60,120].includes(config.interval)) throw new Error("invalid preference");
        autoEnabled = config.enabled; autoInterval = config.interval * 1000;
        announceAuto(autoEnabled ? `Auto-save enabled: ${config.interval} seconds while this page is visible.` : "Auto-save is off. Use Save Draft to keep changes.");
        if (autoEnabled) scheduleAuto();
      }).catch(() => announceAuto("Auto-save preference unavailable. Use Save Draft to keep changes."));
  }

  const make = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text) element.textContent = text;
    return element;
  };
  const to = form.querySelector('input[name="to"]');
  if (to) {
    // This is a conservative presentation parser, never recipient authority.
    // Preserve raw spans: commas inside quoted names are not item separators.
    const parts = (text) => {
      const result = [];
      let start = 0, quoted = false, escaped = false, angle = false;
      for (let index = 0; index < text.length; index++) {
        const character = text[index];
        if (escaped) { escaped = false; continue; }
        if (quoted) {
          if (character === "\\") escaped = true;
          else if (character === '"') quoted = false;
        } else if (character === '"' && !angle) quoted = true;
        else if (character === "<") angle = true;
        else if (character === ">") angle = false;
        else if (character === "," && !angle) {
          result.push({ start, end: index, raw: text.slice(start, index), separated: true });
          start = index + 1;
        }
      }
      result.push({ start, end: text.length, raw: text.slice(start), separated: false });
      return result;
    };
    const recognised = (raw) => {
      const item = raw.trim();
      if (/[\u0000-\u001f\u007f-\u009f]/.test(item)) return false;
      let address = item;
      if (item.includes("<")) {
        const match = item.match(/^("(?:[^"\\<>]|\\[^<>])*"|[^"<>(),:;]*)\s*<\s*([^<>]+?)\s*>$/);
        if (!match || match[1].length > 256) return false;
        address = match[2];
      }
      const match = address.match(/^([A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]+)@([A-Za-z0-9.-]+)$/);
      if (!match || address.length > 320 || match[1].length > 64 ||
          match[1].split(".").some((piece) => !piece) || !match[2].includes(".") || match[2].length > 253) return false;
      return match[2].split(".").every((piece) => piece.length > 0 && piece.length <= 63 && !piece.startsWith("-") && !piece.endsWith("-"));
    };
    const wrapper = make("div", "compose-recipient-editor");
    const chips = make("div", "compose-recipient-chips");
    const editor = make("input", "compose-recipient-input");
    editor.type = "text";
    editor.autocomplete = "off";
    editor.setAttribute("aria-label", "Add recipients");
    editor.placeholder = "Address, then Enter";
    const edit = make("button", "compose-recipient-edit", "Edit all recipients");
    edit.type = "button";
    const label = form.querySelector('label[for="compose-to"]');
    if (label) {
      label.id = label.id || "compose-to-label";
      wrapper.setAttribute("role", "group");
      wrapper.setAttribute("aria-labelledby", label.id);
      label.htmlFor = "compose-recipient-input";
    }
    editor.id = "compose-recipient-input";
    to.before(wrapper);
    wrapper.append(chips, editor, edit, to);
    let prefix = "";
    const renderRecipients = (commitLast) => {
      chips.replaceChildren();
      prefix = "";
      for (const part of parts(to.value)) {
        if (!recognised(part.raw) || (!part.separated && !commitLast)) break;
        const chip = make("span", "compose-recipient-chip");
        const remove = make("button", "compose-recipient-remove", "×");
        remove.type = "button";
        remove.setAttribute("aria-label", `Remove recipient ${part.raw.trim()}`);
        const index = chips.children.length;
        remove.addEventListener("click", () => {
          const end = part.end + (part.separated ? 1 : 0);
          const start = !part.separated && part.start > 0 ? part.start - 1 : part.start;
          to.value = to.value.slice(0, start) + to.value.slice(end);
          renderRecipients(true);
          updateState();
          (chips.querySelectorAll("button")[index] || chips.querySelectorAll("button")[index - 1] || editor).focus();
        });
        chip.append(make("span", "compose-recipient-label", part.raw.trim()), remove);
        chips.append(chip);
        prefix = to.value.slice(0, part.end + (part.separated ? 1 : 0));
      }
      editor.value = to.value.slice(prefix.length);
    };
    editor.addEventListener("input", () => {
      if (prefix && !prefix.trimEnd().endsWith(",") && editor.value) prefix += ", ";
      to.value = prefix + editor.value;
      renderRecipients(false);
      updateState();
    });
    editor.addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.isComposing) {
        event.preventDefault();
        renderRecipients(true);
      } else if (event.key === "Backspace" && !editor.value) {
        const buttons = chips.querySelectorAll("button");
        if (buttons.length) { event.preventDefault(); buttons[buttons.length - 1].focus(); }
      }
    });
    edit.addEventListener("click", () => {
      to.hidden = !to.hidden;
      chips.hidden = editor.hidden = !to.hidden;
      edit.textContent = to.hidden ? "Edit all recipients" : "Use recipient chips";
      if (label) label.htmlFor = to.hidden ? editor.id : to.id;
      if (to.hidden) renderRecipients(true);
      (to.hidden ? editor : to).focus();
    });
    renderRecipients(true);
    to.hidden = true;
  }
  form.addEventListener("click", (event) => {
    if (event.target.closest('a[data-confirm-discard="true"][href="/drafts"]')) submitting = true;
  });

  // Leave the ordinary multiple-file input available if this API is absent.
  const assignFiles = (files) => {
    const transfer = new DataTransfer();
    files.forEach((file) => transfer.items.add(file));
    upload.files = transfer.files;
  };
  try { assignFiles(pending); } catch { return; }

  const bytes = (size) => size < 1024 ? `${size} B` : size < 1048576 ?
    `${(size / 1024).toFixed(1)} KiB` : `${(size / 1048576).toFixed(1)} MiB`;
  const list = make("ul", "saved-attachment-list pending-attachments");
  list.setAttribute("aria-label", "Files waiting to be saved");
  const alert = make("p", "notice notice-error");
  alert.setAttribute("role", "alert");
  alert.hidden = true;
  const add = make("button", "compose-add-files", "+ Add more");
  add.type = "button";
  add.setAttribute("aria-label", "Add more attachments");
  const picker = make("input");
  picker.type = "file";
  picker.multiple = true;
  picker.hidden = true;
  picker.tabIndex = -1;
  const section = upload.closest(".compose-attachments");
  section.append(list, alert, picker);
  heading.after(add);
  upload.hidden = true;
  const label = form.querySelector('label[for="compose-attachment"]');
  if (label) label.hidden = true;
  add.addEventListener("click", () => picker.click());
  const attachShortcut = form.querySelector('a.compose-toolbar-attach[href="#compose-attachment"]');
  if (attachShortcut) attachShortcut.addEventListener("click", (event) => {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    picker.click();
  });

  const stored = () => [...form.querySelectorAll(".saved-attachment[data-bytes]")]
    .filter((row) => !row.querySelector("input").checked);
  const sourceCount = () => form.querySelectorAll('input[name^="include_original_attachment_"]:checked').length;
  const errorFor = (files) => {
    const images = pendingImages();
    if (images.some((file) => !/^[A-Za-z0-9._+ ()-]{1,128}$/.test(file.name)))
      return "Choose an image with a filename of up to 128 characters containing letters, numbers, spaces, dots, underscores, plus, hyphens or parentheses. Your current selection is retained.";
    if (files.some((file) => !/^[A-Za-z0-9._+ ()-]{1,128}$/.test(file.name)))
      return "Use filenames of up to 128 characters containing letters, numbers, spaces, dots, underscores, plus, hyphens or parentheses. The selected files were not added.";
    if (files.length + images.length + stored().length + sourceCount() > 3)
      return "Up to 3 attachments are allowed. Remove a file or deselect a source attachment first.";
    if (images.some((file) => file.size > 5242880))
      return "Images must be 5 MiB or smaller. Choose a smaller image before saving.";
    if (files.some((file) => file.size > 10485760))
      return "Each attachment must be 10 MiB or smaller. The selected files were not added.";
    const total = files.concat(images).reduce((sum, file) => sum + file.size, 0) +
      stored().reduce((sum, row) => sum + Number(row.dataset.bytes), 0);
    if (total > 31457280) return "Attachments must total 30 MiB or less. The selected files were not added.";
    return "";
  };
  const showError = (message) => {
    alert.textContent = message;
    alert.hidden = !message;
  };
  const renderFiles = () => {
    list.replaceChildren();
    pending.forEach((file, index) => {
      const row = make("li", "saved-attachment");
      const description = make("div");
      const filename = make("strong", "", `📄 ${file.name}`);
      filename.dir = "auto";
      description.append(filename, make("span", "muted", `${bytes(file.size)} · not saved yet`));
      const remove = make("button", "pending-attachment-remove", "×");
      remove.type = "button";
      remove.setAttribute("aria-label", `Remove newly added ${file.name}`);
      remove.addEventListener("click", () => {
        pending.splice(index, 1);
        assignFiles(pending);
        showError(errorFor(pending));
        renderFiles();
        const next = list.querySelectorAll("button")[index] || list.querySelector("button") || add;
        next.focus();
      });
      row.append(description, remove);
      list.append(row);
    });
    list.hidden = pending.length === 0;
    heading.textContent = `Attachments (${pending.length + pendingImages().length + stored().length + sourceCount()})`;
    updateState();
  };
  const choose = (files) => {
    const message = errorFor(files);
    if (!message) pending = files;
    assignFiles(pending);
    showError(message);
    renderFiles();
  };
  picker.addEventListener("change", () => {
    choose(pending.concat([...picker.files]));
    picker.value = "";
  });
  upload.addEventListener("change", () => choose([...upload.files]));
  form.addEventListener("change", (event) => {
    if (event.target === imageUpload || (event.target.name && /^(remove_saved_attachment_|include_original_attachment_)/.test(event.target.name))) {
      showError(errorFor(pending));
      renderFiles();
    }
  });
  // Validate only the local file selection. The server checks all source bytes,
  // account bounds and revisions again; this is not a submission authority.
  form.addEventListener("submit", (event) => {
    const message = errorFor(pending);
    if (message) {
      event.preventDefault();
      submitting = false;
      showError(message);
      add.focus();
    }
  });
  renderFiles();
  form.dataset.localControls = "ready";
})();
