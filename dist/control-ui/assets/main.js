(() => {
  const basePath = normalizeBasePath(window.__CARAPACE_CONTROL_UI_BASE_PATH__ || "/ui");
  const assistantName = (window.__CARAPACE_ASSISTANT_NAME__ || "Carapace").trim() || "Carapace";
  const assistantAvatar = (window.__CARAPACE_ASSISTANT_AVATAR__ || "").trim();

  const ui = {
    authType: document.getElementById("authType"),
    authInput: document.getElementById("authInput"),
    saveAuthButton: document.getElementById("saveAuth"),
    clearAuthButton: document.getElementById("clearAuth"),
    toggleAuthVisibilityButton: document.getElementById("toggleAuthVisibility"),
    refreshAllButton: document.getElementById("refreshAll"),
    applyConfigButton: document.getElementById("applyConfig"),
    wsConnectButton: document.getElementById("wsConnect"),
    wsDisconnectButton: document.getElementById("wsDisconnect"),
    wsRefreshPairingsButton: document.getElementById("wsRefreshPairings"),

    statusJson: document.getElementById("statusJson"),
    channelsJson: document.getElementById("channelsJson"),
    channelsCards: document.getElementById("channelsCards"),
    configJson: document.getElementById("configJson"),
    authStatus: document.getElementById("authStatus"),
    configUpdateStatus: document.getElementById("configUpdateStatus"),
    configPathInput: document.getElementById("configPath"),
    configValueInput: document.getElementById("configValue"),
    runtimeBasePath: document.getElementById("runtimeBasePath"),
    transportWarning: document.getElementById("transportWarning"),
    secureContextStatus: document.getElementById("secureContextStatus"),
    pairingStatus: document.getElementById("pairingStatus"),
    pendingPairings: document.getElementById("pendingPairings"),
    pairedDevices: document.getElementById("pairedDevices"),
    pairingEvents: document.getElementById("pairingEvents"),

    assistantNameEl: document.getElementById("assistantName"),
    assistantAvatarEl: document.getElementById("assistantAvatar"),
  };

  const state = {
    authCredential: sessionStorage.getItem("carapace.control.auth") || "",
    authType: sessionStorage.getItem("carapace.control.authType") || "token",
    configHash: null,
    allowInsecureAuth: false,
    isSecureContext: isSecureTransportContext(),

    ws: null,
    wsAuthed: false,
    wsConnectReqId: null,
    wsReqSeq: 0,
    wsPending: new Map(),
    wsNonce: null,

    pairingEvents: [],
  };

  ui.assistantNameEl.textContent = assistantName;
  ui.runtimeBasePath.textContent = `Control UI base path: ${basePath}`;

  if (assistantAvatar) {
    ui.assistantAvatarEl.src = assistantAvatar;
    ui.assistantAvatarEl.classList.remove("hidden");
  }

  if (state.authCredential) {
    ui.authInput.value = state.authCredential;
    setAuthStatus("Credential loaded from this browser session.", false);
  }
  ui.authType.value = state.authType;

  if (!state.isSecureContext) {
    ui.transportWarning.hidden = false;
  }

  updateSecurityContextStatus();
  updateWsButtons();

  ui.saveAuthButton.addEventListener("click", onSaveCredential);
  ui.clearAuthButton.addEventListener("click", onClearCredential);
  ui.toggleAuthVisibilityButton.addEventListener("click", onToggleAuthVisibility);
  ui.refreshAllButton.addEventListener("click", () => refreshAll().catch(noop));
  ui.applyConfigButton.addEventListener("click", () => applyConfigUpdate().catch(noop));
  ui.wsConnectButton.addEventListener("click", () => connectPairingSocket().catch(noop));
  ui.wsDisconnectButton.addEventListener("click", disconnectPairingSocket);
  ui.wsRefreshPairingsButton.addEventListener("click", () => refreshPairings().catch(noop));

  ui.pendingPairings.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action][data-request-id]");
    if (!button) {
      return;
    }
    const requestId = button.dataset.requestId;
    if (!requestId) {
      return;
    }
    const action = button.dataset.action;
    if (action === "approve") {
      approvePairing(requestId).catch(noop);
    } else if (action === "reject") {
      rejectPairing(requestId).catch(noop);
    }
  });

  if (state.authCredential) {
    refreshAll().catch((err) => {
      setAuthStatus(String(err), true);
    });
  } else {
    setAuthStatus("Enter credential and click 'Use credential' to load Control API data.", false);
  }

  async function refreshAll() {
    const credential = currentCredential();
    if (!credential) {
      throw new Error("credential required");
    }

    setBusy(true);
    ui.configUpdateStatus.textContent = "";
    try {
      const [status, channels, configResponse] = await Promise.all([
        controlGet("/control/status"),
        controlGet("/control/channels"),
        controlGet("/control/config"),
      ]);

      renderJson(ui.statusJson, status);
      renderJson(ui.channelsJson, channels);
      renderChannels(channels);
      renderJson(ui.configJson, configResponse);

      state.configHash = typeof configResponse.hash === "string" ? configResponse.hash : null;

      const configRoot = configResponse && typeof configResponse.config === "object" ? configResponse.config : {};
      state.allowInsecureAuth = Boolean(
        dig(configRoot, ["gateway", "controlUi", "allowInsecureAuth"]) ||
          dig(configRoot, ["gateway", "controlUi", "allow_insecure_auth"])
      );
      updateSecurityContextStatus();

      await ensureAssistantAvatar(configRoot);
      setAuthStatus("Control API read successful.", false);
    } finally {
      setBusy(false);
    }
  }

  async function ensureAssistantAvatar(configRoot) {
    if (assistantAvatar) {
      return;
    }

    const candidateIds = [];

    const agents = dig(configRoot, ["agents", "list"]);
    if (Array.isArray(agents)) {
      const defaultAgent = agents.find((agent) => agent && agent.default === true && typeof agent.id === "string");
      if (defaultAgent) {
        candidateIds.push(defaultAgent.id);
      }
      const firstAgent = agents.find((agent) => agent && typeof agent.id === "string");
      if (firstAgent) {
        candidateIds.push(firstAgent.id);
      }
    }

    candidateIds.push("main", "default");

    for (const id of dedupeStrings(candidateIds)) {
      const avatarMetaUrl = `${basePath}/__carapace_avatar__/${encodeURIComponent(id)}?meta=1`;
      try {
        const response = await fetch(avatarMetaUrl, { credentials: "same-origin" });
        if (!response.ok) {
          continue;
        }
        const body = await response.json();
        if (body && typeof body.avatarUrl === "string" && body.avatarUrl.length > 0) {
          ui.assistantAvatarEl.src = body.avatarUrl;
          ui.assistantAvatarEl.classList.remove("hidden");
          return;
        }
      } catch (_err) {
        // Keep searching candidate IDs.
      }
    }
  }

  async function applyConfigUpdate() {
    ui.configUpdateStatus.textContent = "";

    const path = ui.configPathInput.value.trim();
    if (!path) {
      setConfigStatus("Path is required.", true);
      return;
    }

    let parsedValue;
    try {
      parsedValue = JSON.parse(ui.configValueInput.value);
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
      if (state.configHash) {
        body.baseHash = state.configHash;
      }

      const response = await controlPost("/control/config", body);
      renderJson(ui.configJson, response);
      if (typeof response.hash === "string") {
        state.configHash = response.hash;
      }

      await refreshAll();
      setConfigStatus("Config update applied.", false);
    } catch (err) {
      setConfigStatus(String(err), true);
    } finally {
      setBusy(false);
    }
  }

  async function connectPairingSocket() {
    const credential = currentCredential();
    if (!credential) {
      setPairingStatus("Credential required before opening pairing socket.", true);
      return;
    }

    if (!state.isSecureContext && !state.allowInsecureAuth) {
      setPairingStatus(
        "Pairing socket blocked: use HTTPS/localhost or set gateway.controlUi.allowInsecureAuth=true.",
        true
      );
      return;
    }

    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      setPairingStatus("Pairing socket already connected.", false);
      return;
    }

    disconnectPairingSocket();

    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsProtocol}//${window.location.host}/ws`;

    setPairingStatus(`Connecting to ${wsUrl} ...`, false);

    const ws = new WebSocket(wsUrl);
    state.ws = ws;
    state.wsAuthed = false;
    state.wsNonce = null;
    state.wsConnectReqId = null;
    clearWsPending(new Error("socket reset"));
    updateWsButtons();

    ws.onopen = () => {
      setPairingStatus("Socket open. Waiting for connect.challenge ...", false);
      updateWsButtons();
    };

    ws.onmessage = (event) => {
      handleWsFrame(event.data);
    };

    ws.onerror = () => {
      setPairingStatus("WebSocket transport error.", true);
    };

    ws.onclose = (event) => {
      const message = event.code === 1000 ? "Pairing socket closed." : `Pairing socket closed (${event.code}).`;
      setPairingStatus(message, event.code !== 1000);
      clearWsPending(new Error("socket closed"));
      state.ws = null;
      state.wsAuthed = false;
      state.wsNonce = null;
      state.wsConnectReqId = null;
      updateWsButtons();
    };
  }

  function disconnectPairingSocket() {
    if (state.ws) {
      try {
        state.ws.close(1000, "client disconnect");
      } catch (_err) {
        // Ignore close errors.
      }
    }
    clearWsPending(new Error("socket disconnected"));
    state.ws = null;
    state.wsAuthed = false;
    state.wsNonce = null;
    state.wsConnectReqId = null;
    updateWsButtons();
  }

  async function refreshPairings() {
    if (!state.wsAuthed) {
      throw new Error("pairing socket not authenticated");
    }
    const payload = await wsRequest("device.pair.list", {});
    renderPairingLists(payload);
  }

  async function approvePairing(requestId) {
    if (!state.wsAuthed) {
      setPairingStatus("Pairing socket not authenticated.", true);
      return;
    }
    await wsRequest("device.pair.approve", { requestId });
    appendPairingEvent({ type: "operator.approve", requestId, ts: Date.now() });
    setPairingStatus(`Approved pairing request ${requestId}.`, false);
    await refreshPairings();
  }

  async function rejectPairing(requestId) {
    if (!state.wsAuthed) {
      setPairingStatus("Pairing socket not authenticated.", true);
      return;
    }
    await wsRequest("device.pair.reject", { requestId });
    appendPairingEvent({ type: "operator.reject", requestId, ts: Date.now() });
    setPairingStatus(`Rejected pairing request ${requestId}.`, false);
    await refreshPairings();
  }

  function handleWsFrame(raw) {
    let frame;
    try {
      frame = JSON.parse(raw);
    } catch (_err) {
      return;
    }

    if (!frame || typeof frame !== "object") {
      return;
    }

    if (frame.type === "event") {
      if (frame.event === "connect.challenge") {
        const nonce = frame.payload && frame.payload.nonce;
        if (typeof nonce === "string" && nonce) {
          state.wsNonce = nonce;
          sendConnectRequest();
        }
        return;
      }

      if (frame.event === "device.pair.requested" || frame.event === "device.pair.resolved") {
        appendPairingEvent({ type: frame.event, payload: frame.payload || {}, ts: Date.now() });
        if (state.wsAuthed) {
          refreshPairings().catch(noop);
        }
        return;
      }

      return;
    }

    if (frame.type === "res" && typeof frame.id === "string") {
      if (state.wsConnectReqId && frame.id === state.wsConnectReqId) {
        if (frame.ok) {
          state.wsAuthed = true;
          setPairingStatus("Pairing socket authenticated.", false);
          updateWsButtons();
          refreshPairings().catch((err) => setPairingStatus(String(err), true));
        } else {
          const message = errorMessageFromFrame(frame) || "connect failed";
          setPairingStatus(`Pairing connect failed: ${message}`, true);
          disconnectPairingSocket();
        }
        return;
      }

      const pending = state.wsPending.get(frame.id);
      if (!pending) {
        return;
      }
      state.wsPending.delete(frame.id);
      clearTimeout(pending.timer);
      if (frame.ok) {
        pending.resolve(frame.payload || {});
      } else {
        pending.reject(new Error(errorMessageFromFrame(frame) || "request failed"));
      }
    }
  }

  function sendConnectRequest() {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN) {
      return;
    }

    const nonce = state.wsNonce;
    if (!nonce) {
      return;
    }

    const credential = currentCredential();
    if (!credential) {
      setPairingStatus("Credential missing while connecting pairing socket.", true);
      return;
    }

    const reqId = `connect-${Date.now()}`;
    state.wsConnectReqId = reqId;

    const params = {
      minProtocol: 3,
      maxProtocol: 3,
      role: "operator",
      scopes: ["operator.admin", "operator.pairing"],
      client: {
        id: "carapace-control-ui",
        version: "0.1.0",
        platform: navigator.platform || "web",
        mode: "ui",
      },
      auth: {},
    };

    if (state.authType === "password") {
      params.auth.password = credential;
    } else {
      params.auth.token = credential;
    }

    const frame = {
      type: "req",
      id: reqId,
      method: "connect",
      params,
    };

    try {
      state.ws.send(JSON.stringify(frame));
      setPairingStatus("Sent connect request for pairing socket ...", false);
    } catch (err) {
      setPairingStatus(`Failed to send connect request: ${err}`, true);
      disconnectPairingSocket();
    }
  }

  function wsRequest(method, params) {
    if (!state.ws || state.ws.readyState !== WebSocket.OPEN || !state.wsAuthed) {
      return Promise.reject(new Error("pairing socket not connected"));
    }

    const reqId = `ui-${++state.wsReqSeq}`;
    const frame = {
      type: "req",
      id: reqId,
      method,
      params,
    };

    return new Promise((resolve, reject) => {
      const timer = window.setTimeout(() => {
        state.wsPending.delete(reqId);
        reject(new Error(`${method} timed out`));
      }, 10000);

      state.wsPending.set(reqId, { resolve, reject, timer });

      try {
        state.ws.send(JSON.stringify(frame));
      } catch (err) {
        window.clearTimeout(timer);
        state.wsPending.delete(reqId);
        reject(err);
      }
    });
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
    const credential = currentCredential();
    if (!credential) {
      return {};
    }
    return {
      Authorization: `Bearer ${credential}`,
    };
  }

  function currentCredential() {
    return ui.authInput.value.trim() || state.authCredential;
  }

  async function parseResponse(response) {
    const text = await response.text();
    let body = {};
    if (text) {
      try {
        body = JSON.parse(text);
      } catch (_err) {
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

  function renderChannels(channelsPayload) {
    const channels = Array.isArray(channelsPayload && channelsPayload.channels)
      ? channelsPayload.channels
      : [];

    if (!channels.length) {
      ui.channelsCards.innerHTML = "<div class=\"card\"><div class=\"detail\">No channels configured.</div></div>";
      return;
    }

    const cards = channels
      .map((channel) => {
        const name = escapeHtml(String(channel.name || channel.id || "unknown"));
        const status = escapeHtml(String(channel.status || "unknown"));
        const connectedAt = channel.lastConnectedAt ? escapeHtml(String(channel.lastConnectedAt)) : "-";
        const error = channel.lastError ? `<div class=\"detail error\">${escapeHtml(String(channel.lastError))}</div>` : "";
        return `
          <article class="card">
            <div class="title">${name}</div>
            <div class="detail">status: ${status}</div>
            <div class="detail">last connected: ${connectedAt}</div>
            ${error}
          </article>
        `;
      })
      .join("");

    ui.channelsCards.innerHTML = cards;
  }

  function renderPairingLists(payload) {
    const pending = Array.isArray(payload && payload.pending) ? payload.pending : [];
    const paired = Array.isArray(payload && payload.paired) ? payload.paired : [];

    if (!pending.length) {
      ui.pendingPairings.innerHTML = "<div class=\"card\"><div class=\"detail\">No pending pairing requests.</div></div>";
    } else {
      ui.pendingPairings.innerHTML = pending
        .map((item) => {
          const requestId = escapeHtml(String(item.requestId || ""));
          const deviceId = escapeHtml(String(item.deviceId || "unknown"));
          const displayName = escapeHtml(String(item.displayName || "(no display name)"));
          const remoteIp = escapeHtml(String(item.remoteIp || "local"));
          return `
            <article class="card">
              <div class="title">${displayName}</div>
              <div class="detail">requestId: ${requestId}</div>
              <div class="detail">deviceId: ${deviceId}</div>
              <div class="detail">remoteIp: ${remoteIp}</div>
              <div class="row">
                <button data-action="approve" data-request-id="${requestId}">Approve</button>
                <button class="danger" data-action="reject" data-request-id="${requestId}">Reject</button>
              </div>
            </article>
          `;
        })
        .join("");
    }

    if (!paired.length) {
      ui.pairedDevices.innerHTML = "<div class=\"card\"><div class=\"detail\">No paired devices.</div></div>";
      return;
    }

    ui.pairedDevices.innerHTML = paired
      .map((item) => {
        const deviceId = escapeHtml(String(item.deviceId || "unknown"));
        const displayName = escapeHtml(String(item.displayName || "(no display name)"));
        const platform = escapeHtml(String(item.platform || "unknown"));
        const lastSeen = item.lastSeenAtMs ? escapeHtml(new Date(Number(item.lastSeenAtMs)).toISOString()) : "-";
        return `
          <article class="card">
            <div class="title">${displayName}</div>
            <div class="detail">deviceId: ${deviceId}</div>
            <div class="detail">platform: ${platform}</div>
            <div class="detail">lastSeen: ${lastSeen}</div>
          </article>
        `;
      })
      .join("");
  }

  function appendPairingEvent(entry) {
    state.pairingEvents.unshift(entry);
    if (state.pairingEvents.length > 100) {
      state.pairingEvents = state.pairingEvents.slice(0, 100);
    }
    renderJson(ui.pairingEvents, state.pairingEvents);
  }

  function onSaveCredential() {
    state.authCredential = ui.authInput.value.trim();
    state.authType = ui.authType.value === "password" ? "password" : "token";

    if (!state.authCredential) {
      setAuthStatus("Enter a credential.", true);
      return;
    }

    sessionStorage.setItem("carapace.control.auth", state.authCredential);
    sessionStorage.setItem("carapace.control.authType", state.authType);
    setAuthStatus(`Credential loaded for this browser session (${state.authType}).`, false);

    refreshAll().catch((err) => setAuthStatus(String(err), true));
  }

  function onClearCredential() {
    state.authCredential = "";
    ui.authInput.value = "";
    sessionStorage.removeItem("carapace.control.auth");
    setAuthStatus("Credential cleared.", false);
    disconnectPairingSocket();
  }

  function onToggleAuthVisibility() {
    const nextType = ui.authInput.type === "password" ? "text" : "password";
    ui.authInput.type = nextType;
    ui.toggleAuthVisibilityButton.textContent = nextType === "password" ? "Show" : "Hide";
  }

  function setBusy(busy) {
    ui.refreshAllButton.disabled = busy;
    ui.applyConfigButton.disabled = busy;
    ui.saveAuthButton.disabled = busy;
    ui.clearAuthButton.disabled = busy;
  }

  function setAuthStatus(message, isError) {
    ui.authStatus.textContent = message;
    ui.authStatus.classList.toggle("error", Boolean(isError));
    ui.authStatus.classList.toggle("success", !isError);
  }

  function setConfigStatus(message, isError) {
    ui.configUpdateStatus.textContent = message;
    ui.configUpdateStatus.classList.toggle("error", Boolean(isError));
    ui.configUpdateStatus.classList.toggle("success", !isError);
  }

  function setPairingStatus(message, isError) {
    ui.pairingStatus.textContent = message;
    ui.pairingStatus.classList.toggle("error", Boolean(isError));
    ui.pairingStatus.classList.toggle("success", !isError);
  }

  function updateSecurityContextStatus() {
    const base = state.isSecureContext ? "Secure transport context detected." : "Insecure transport context detected.";
    const policy = state.allowInsecureAuth
      ? "gateway.controlUi.allowInsecureAuth=true allows remote insecure auth paths."
      : "gateway.controlUi.allowInsecureAuth=false keeps insecure auth paths blocked.";
    ui.secureContextStatus.textContent = `${base} ${policy}`;
  }

  function updateWsButtons() {
    const open = state.ws && state.ws.readyState === WebSocket.OPEN;
    const ready = open && state.wsAuthed;

    ui.wsConnectButton.disabled = open;
    ui.wsDisconnectButton.disabled = !open;
    ui.wsRefreshPairingsButton.disabled = !ready;
  }

  function clearWsPending(error) {
    for (const { reject, timer } of state.wsPending.values()) {
      clearTimeout(timer);
      reject(error);
    }
    state.wsPending.clear();
  }

  function errorMessageFromFrame(frame) {
    if (!frame || typeof frame !== "object") {
      return null;
    }
    if (frame.error && typeof frame.error.message === "string") {
      return frame.error.message;
    }
    if (typeof frame.error === "string") {
      return frame.error;
    }
    return null;
  }

  function normalizeBasePath(path) {
    const trimmed = String(path || "").trim();
    if (!trimmed || trimmed === "__CARAPACE_CONTROL_UI_BASE_PATH__") {
      return "/ui";
    }
    return trimmed.endsWith("/") ? trimmed.slice(0, -1) : trimmed;
  }

  function isSecureTransportContext() {
    const host = window.location.hostname;
    const isLocalHost = host === "localhost" || host === "127.0.0.1" || host === "::1";
    return window.location.protocol === "https:" || isLocalHost;
  }

  function dig(value, path) {
    let current = value;
    for (const key of path) {
      if (!current || typeof current !== "object" || !(key in current)) {
        return undefined;
      }
      current = current[key];
    }
    return current;
  }

  function dedupeStrings(values) {
    const seen = new Set();
    const out = [];
    for (const value of values) {
      if (typeof value !== "string") {
        continue;
      }
      const trimmed = value.trim();
      if (!trimmed || seen.has(trimmed)) {
        continue;
      }
      seen.add(trimmed);
      out.push(trimmed);
    }
    return out;
  }

  function escapeHtml(value) {
    return value
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function noop() {
    // Explicit no-op for background Promise chains.
  }
})();
