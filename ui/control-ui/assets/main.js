(() => {
  const basePath = normalizeBasePath(window.__CARAPACE_CONTROL_UI_BASE_PATH__ || "/ui");
  const assistantName = (window.__CARAPACE_ASSISTANT_NAME__ || "Carapace").trim() || "Carapace";
  const assistantAvatar = (window.__CARAPACE_ASSISTANT_AVATAR__ || "").trim();

  const authInput = document.getElementById("authInput");
  const saveAuthButton = document.getElementById("saveAuth");
  const clearAuthButton = document.getElementById("clearAuth");
  const toggleAuthVisibilityButton = document.getElementById("toggleAuthVisibility");
  const refreshAllButton = document.getElementById("refreshAll");
  const applyConfigButton = document.getElementById("applyConfig");

  const statusJson = document.getElementById("statusJson");
  const channelsJson = document.getElementById("channelsJson");
  const configJson = document.getElementById("configJson");
  const authStatus = document.getElementById("authStatus");
  const configUpdateStatus = document.getElementById("configUpdateStatus");
  const configPathInput = document.getElementById("configPath");
  const configValueInput = document.getElementById("configValue");
  const runtimeBasePath = document.getElementById("runtimeBasePath");
  const transportWarning = document.getElementById("transportWarning");

  const assistantNameEl = document.getElementById("assistantName");
  const assistantAvatarEl = document.getElementById("assistantAvatar");

  assistantNameEl.textContent = assistantName;
  runtimeBasePath.textContent = `Control UI base path: ${basePath}`;

  if (assistantAvatar) {
    assistantAvatarEl.src = assistantAvatar;
    assistantAvatarEl.classList.remove("hidden");
  }

  if (requiresTransportWarning()) {
    transportWarning.hidden = false;
  }

  let authCredential = sessionStorage.getItem("carapace.control.auth") || "";
  let configHash = null;

  if (authCredential) {
    authInput.value = authCredential;
    setAuthStatus("Credential loaded from this browser session.", false);
  }

  saveAuthButton.addEventListener("click", () => {
    authCredential = authInput.value.trim();
    if (!authCredential) {
      setAuthStatus("Enter a token or password.", true);
      return;
    }
    sessionStorage.setItem("carapace.control.auth", authCredential);
    setAuthStatus("Credential loaded for this browser session.", false);
  });

  clearAuthButton.addEventListener("click", () => {
    authCredential = "";
    authInput.value = "";
    sessionStorage.removeItem("carapace.control.auth");
    setAuthStatus("Credential cleared.", false);
  });

  toggleAuthVisibilityButton.addEventListener("click", () => {
    const nextType = authInput.type === "password" ? "text" : "password";
    authInput.type = nextType;
    toggleAuthVisibilityButton.textContent = nextType === "password" ? "Show" : "Hide";
  });

  refreshAllButton.addEventListener("click", async () => {
    await refreshAll();
  });

  applyConfigButton.addEventListener("click", async () => {
    await applyConfigUpdate();
  });

  refreshAll().catch((err) => {
    setAuthStatus(String(err), true);
  });

  async function refreshAll() {
    setBusy(true);
    configUpdateStatus.textContent = "";
    try {
      const [status, channels, config] = await Promise.all([
        controlGet("/control/status"),
        controlGet("/control/channels"),
        controlGet("/control/config"),
      ]);
      renderJson(statusJson, status);
      renderJson(channelsJson, channels);
      renderJson(configJson, config);
      configHash = typeof config.hash === "string" ? config.hash : null;
      setAuthStatus("Control API read successful.", false);
    } catch (err) {
      setAuthStatus(String(err), true);
      throw err;
    } finally {
      setBusy(false);
    }
  }

  async function applyConfigUpdate() {
    configUpdateStatus.textContent = "";

    const path = configPathInput.value.trim();
    if (!path) {
      setConfigStatus("Path is required.", true);
      return;
    }

    let parsedValue;
    try {
      parsedValue = JSON.parse(configValueInput.value);
    } catch (err) {
      setConfigStatus(`Value must be valid JSON: ${err}`, true);
      return;
    }

    setBusy(true);
    try {
      const body = {
        path,
        value: parsedValue,
      };
      if (configHash) {
        body.baseHash = configHash;
      }

      const response = await controlPost("/control/config", body);
      renderJson(configJson, response);
      if (typeof response.hash === "string") {
        configHash = response.hash;
      }

      await refreshAll();
      setConfigStatus("Config update applied.", false);
    } catch (err) {
      setConfigStatus(String(err), true);
    } finally {
      setBusy(false);
    }
  }

  async function controlGet(path) {
    const response = await fetch(path, {
      method: "GET",
      headers: authHeaders(),
      credentials: "same-origin",
    });
    return parseResponse(response);
  }

  async function controlPost(path, body) {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...authHeaders(),
      },
      credentials: "same-origin",
      body: JSON.stringify(body),
    });
    return parseResponse(response);
  }

  function authHeaders() {
    const credential = authInput.value.trim() || authCredential;
    if (!credential) {
      return {};
    }
    return {
      Authorization: `Bearer ${credential}`,
    };
  }

  async function parseResponse(response) {
    const text = await response.text();
    let body = {};
    if (text) {
      try {
        body = JSON.parse(text);
      } catch (err) {
        body = { raw: text };
      }
    }

    if (!response.ok) {
      const message =
        (body && body.error) ||
        (body && body.message) ||
        `HTTP ${response.status} ${response.statusText}`;
      throw new Error(message);
    }
    return body;
  }

  function renderJson(target, value) {
    target.textContent = JSON.stringify(value, null, 2);
  }

  function setBusy(busy) {
    refreshAllButton.disabled = busy;
    applyConfigButton.disabled = busy;
    saveAuthButton.disabled = busy;
    clearAuthButton.disabled = busy;
  }

  function setAuthStatus(message, isError) {
    authStatus.textContent = message;
    authStatus.classList.toggle("error", !!isError);
    authStatus.classList.toggle("success", !isError);
  }

  function setConfigStatus(message, isError) {
    configUpdateStatus.textContent = message;
    configUpdateStatus.classList.toggle("error", !!isError);
    configUpdateStatus.classList.toggle("success", !isError);
  }

  function normalizeBasePath(path) {
    const trimmed = String(path || "").trim();
    if (!trimmed || trimmed === "__CARAPACE_CONTROL_UI_BASE_PATH__") {
      return "/ui";
    }
    return trimmed.endsWith("/") ? trimmed.slice(0, -1) : trimmed;
  }

  function requiresTransportWarning() {
    const host = window.location.hostname;
    const isLocalHost = host === "localhost" || host === "127.0.0.1" || host === "::1";
    return !(window.location.protocol === "https:" || isLocalHost);
  }
})();
