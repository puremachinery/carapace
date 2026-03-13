(() => {
  const runtimeConfig = loadRuntimeConfig();
  const basePath = normalizeBasePath(runtimeConfig.basePath || "/ui");
  const assistantName = (runtimeConfig.assistantName || "Carapace").trim() || "Carapace";
  const assistantAvatar = (runtimeConfig.assistantAvatar || "").trim();
  const csrfCookieName = runtimeConfig.csrfCookieName;
  const csrfHeaderName = runtimeConfig.csrfHeaderName;

  const ui = {
    authType: document.getElementById("authType"),
    authInput: document.getElementById("authInput"),
    saveAuthButton: document.getElementById("saveAuth"),
    clearAuthButton: document.getElementById("clearAuth"),
    toggleAuthVisibilityButton: document.getElementById("toggleAuthVisibility"),
    refreshAllButton: document.getElementById("refreshAll"),
    applyConfigButton: document.getElementById("applyConfig"),
    saveControlUiSettingsButton: document.getElementById("saveControlUiSettings"),
    geminiAuthModeSelect: document.getElementById("geminiAuthMode"),
    geminiOauthFields: document.getElementById("geminiOauthFields"),
    geminiApiKeyFields: document.getElementById("geminiApiKeyFields"),
    geminiClientIdInput: document.getElementById("geminiClientId"),
    geminiClientSecretInput: document.getElementById("geminiClientSecret"),
    geminiStartOauthButton: document.getElementById("geminiStartOauth"),
    geminiRefreshOauthButton: document.getElementById("geminiRefreshOauth"),
    geminiApplyOauthButton: document.getElementById("geminiApplyOauth"),
    geminiApiKeyInput: document.getElementById("geminiApiKey"),
    geminiBaseUrlInput: document.getElementById("geminiBaseUrl"),
    geminiSaveApiKeyButton: document.getElementById("geminiSaveApiKey"),
    wsConnectButton: document.getElementById("wsConnect"),
    wsDisconnectButton: document.getElementById("wsDisconnect"),
    wsRefreshPairingsButton: document.getElementById("wsRefreshPairings"),
    refreshTasksButton: document.getElementById("refreshTasks"),
    taskCancelButton: document.getElementById("taskCancel"),
    taskRetryButton: document.getElementById("taskRetry"),
    taskResumeButton: document.getElementById("taskResume"),
    taskApplyPatchButton: document.getElementById("taskApplyPatch"),

    statusJson: document.getElementById("statusJson"),
    channelsJson: document.getElementById("channelsJson"),
    channelsCards: document.getElementById("channelsCards"),
    configJson: document.getElementById("configJson"),
    authStatus: document.getElementById("authStatus"),
    geminiOnboardingStatus: document.getElementById("geminiOnboardingStatus"),
    configUpdateStatus: document.getElementById("configUpdateStatus"),
    controlUiSettingsStatus: document.getElementById("controlUiSettingsStatus"),
    configPathInput: document.getElementById("configPath"),
    configValueInput: document.getElementById("configValue"),
    controlUiEnabledInput: document.getElementById("controlUiEnabled"),
    controlUiBasePathInput: document.getElementById("controlUiBasePath"),
    controlUiAllowInsecureAuthInput: document.getElementById("controlUiAllowInsecureAuth"),
    controlUiDisableDeviceAuthInput: document.getElementById("controlUiDisableDeviceAuth"),
    runtimeBasePath: document.getElementById("runtimeBasePath"),
    transportWarning: document.getElementById("transportWarning"),
    secureContextStatus: document.getElementById("secureContextStatus"),
    pairingStatus: document.getElementById("pairingStatus"),
    pendingPairings: document.getElementById("pendingPairings"),
    pairedDevices: document.getElementById("pairedDevices"),
    pairingEvents: document.getElementById("pairingEvents"),
    taskFilterState: document.getElementById("taskFilterState"),
    tasksCards: document.getElementById("tasksCards"),
    taskDetailJson: document.getElementById("taskDetailJson"),
    taskActionReasonInput: document.getElementById("taskActionReason"),
    taskActionDelayMsInput: document.getElementById("taskActionDelayMs"),
    taskPatchPayloadInput: document.getElementById("taskPatchPayload"),
    taskPatchMaxAttemptsInput: document.getElementById("taskPatchMaxAttempts"),
    taskPatchMaxTotalRuntimeMsInput: document.getElementById("taskPatchMaxTotalRuntimeMs"),
    taskPatchMaxTurnsInput: document.getElementById("taskPatchMaxTurns"),
    taskPatchMaxRunTimeoutSecondsInput: document.getElementById("taskPatchMaxRunTimeoutSeconds"),
    taskStatus: document.getElementById("taskStatus"),

    assistantNameEl: document.getElementById("assistantName"),
    assistantAvatarEl: document.getElementById("assistantAvatar"),
  };

  const state = {
    authCredential: sessionStorage.getItem("carapace.control.auth") || "",
    authType: sessionStorage.getItem("carapace.control.authType") || "token",
    configHash: null,
    allowInsecureAuth: false,
    isSecureContext: isSecureTransportContext(),
    controlUiConfig: {
      enabled: false,
      basePath: "",
      allowInsecureAuth: false,
      disableDeviceAuth: false,
    },
    currentConfigRoot: {},
    geminiFlowId: null,
    isBusy: false,

    ws: null,
    wsAuthed: false,
    wsConnectReqId: null,
    wsReqSeq: 0,
    wsPending: new Map(),
    wsNonce: null,

    pairingEvents: [],
    tasks: [],
    selectedTaskId: null,
    selectedTask: null,
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

  renderJson(ui.taskDetailJson, {});
  updateSecurityContextStatus();
  renderGeminiOnboardingForm();
  updateWsButtons();
  updateTaskActionButtons();

  ui.saveAuthButton.addEventListener("click", onSaveCredential);
  ui.clearAuthButton.addEventListener("click", onClearCredential);
  ui.toggleAuthVisibilityButton.addEventListener("click", onToggleAuthVisibility);
  ui.refreshAllButton.addEventListener("click", () => refreshAll().catch(noop));
  ui.applyConfigButton.addEventListener("click", () => applyConfigUpdate().catch(noop));
  ui.saveControlUiSettingsButton.addEventListener("click", () => saveControlUiSettings().catch(noop));
  ui.geminiAuthModeSelect.addEventListener("change", renderGeminiOnboardingForm);
  ui.geminiStartOauthButton.addEventListener("click", () => startGeminiOauth().catch(noop));
  ui.geminiRefreshOauthButton.addEventListener("click", () => refreshGeminiOauthStatus().catch(noop));
  ui.geminiApplyOauthButton.addEventListener("click", () => applyGeminiOauth().catch(noop));
  ui.geminiSaveApiKeyButton.addEventListener("click", () => saveGeminiApiKey().catch(noop));
  ui.wsConnectButton.addEventListener("click", () => connectPairingSocket().catch(noop));
  ui.wsDisconnectButton.addEventListener("click", disconnectPairingSocket);
  ui.wsRefreshPairingsButton.addEventListener("click", () => refreshPairings().catch(noop));
  ui.refreshTasksButton.addEventListener("click", () => refreshTasks(false).catch(noop));
  ui.taskFilterState.addEventListener("change", () => refreshTasks(false).catch(noop));
  ui.taskCancelButton.addEventListener("click", () => cancelSelectedTask().catch(noop));
  ui.taskRetryButton.addEventListener("click", () => retrySelectedTask().catch(noop));
  ui.taskResumeButton.addEventListener("click", () => resumeSelectedTask().catch(noop));
  ui.taskApplyPatchButton.addEventListener("click", () => patchSelectedTask().catch(noop));

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

  ui.tasksCards.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-task-id]");
    if (!button) {
      return;
    }
    const taskId = button.dataset.taskId;
    if (!taskId) {
      return;
    }
    selectTask(taskId).catch(noop);
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
    ui.controlUiSettingsStatus.textContent = "";
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
      state.currentConfigRoot =
        configResponse && typeof configResponse.config === "object" ? configResponse.config : {};

      applyControlUiFormFromConfig(state.currentConfigRoot);
      applyGeminiFormFromConfig(state.currentConfigRoot);
      updateSecurityContextStatus();
      await ensureAssistantAvatar(state.currentConfigRoot);
      try {
        await refreshTasks(true);
      } catch (err) {
        setTaskStatus(String(err), true);
      }
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

  function applyControlUiFormFromConfig(configRoot) {
    const controlUi = dig(configRoot, ["gateway", "controlUi"]);
    const next = {
      enabled: Boolean(controlUi && controlUi.enabled),
      basePath: typeof (controlUi && controlUi.basePath) === "string" ? controlUi.basePath : "",
      allowInsecureAuth: Boolean(
        controlUi && (controlUi.allowInsecureAuth === true || controlUi.allow_insecure_auth === true)
      ),
      disableDeviceAuth: Boolean(
        controlUi && (controlUi.disableDeviceAuth === true || controlUi.disable_device_auth === true)
      ),
    };
    state.controlUiConfig = next;
    state.allowInsecureAuth = next.allowInsecureAuth;

    ui.controlUiEnabledInput.checked = next.enabled;
    ui.controlUiBasePathInput.value = next.basePath;
    ui.controlUiAllowInsecureAuthInput.checked = next.allowInsecureAuth;
    ui.controlUiDisableDeviceAuthInput.checked = next.disableDeviceAuth;
  }

  function applyGeminiFormFromConfig(configRoot) {
    const google = dig(configRoot, ["google"]) || {};
    const authProfile = typeof google.authProfile === "string" ? google.authProfile : "";
    const apiKeyConfigured = typeof google.apiKey === "string" && google.apiKey.length > 0;
    const baseUrl = typeof google.baseUrl === "string" ? google.baseUrl : "";
    const hasConflict = apiKeyConfigured && !!authProfile;

    ui.geminiAuthModeSelect.value = !apiKeyConfigured && authProfile ? "oauth" : "api-key";
    ui.geminiBaseUrlInput.value = baseUrl;

    if (hasConflict) {
      setGeminiOnboardingStatus(
        `Both a Google auth profile (${authProfile}) and a Gemini API key are configured. The API key will be used until you remove it.`,
        false
      );
    } else if (authProfile) {
      setGeminiOnboardingStatus(`Gemini is configured to use Google auth profile ${authProfile}.`, false);
    } else if (apiKeyConfigured) {
      setGeminiOnboardingStatus("Gemini is configured to use an API key.", false);
    } else {
      setGeminiOnboardingStatus("Gemini is not configured yet.", false);
    }

    renderGeminiOnboardingForm();
  }

  function renderGeminiOnboardingForm() {
    const mode = ui.geminiAuthModeSelect.value === "api-key" ? "api-key" : "oauth";
    ui.geminiOauthFields.hidden = mode !== "oauth";
    ui.geminiApiKeyFields.hidden = mode !== "api-key";
    ui.geminiRefreshOauthButton.disabled = state.isBusy || !state.geminiFlowId;
    ui.geminiApplyOauthButton.disabled = state.isBusy || !state.geminiFlowId;
  }

  async function saveControlUiSettings() {
    const updates = [];
    const desired = {
      enabled: Boolean(ui.controlUiEnabledInput.checked),
      basePath: ui.controlUiBasePathInput.value.trim(),
      allowInsecureAuth: Boolean(ui.controlUiAllowInsecureAuthInput.checked),
      disableDeviceAuth: Boolean(ui.controlUiDisableDeviceAuthInput.checked),
    };

    if (desired.enabled !== state.controlUiConfig.enabled) {
      updates.push({ path: "gateway.controlUi.enabled", value: desired.enabled });
    }
    if (desired.basePath !== state.controlUiConfig.basePath) {
      updates.push({ path: "gateway.controlUi.basePath", value: desired.basePath });
    }
    if (desired.allowInsecureAuth !== state.controlUiConfig.allowInsecureAuth) {
      updates.push({
        path: "gateway.controlUi.allowInsecureAuth",
        value: desired.allowInsecureAuth,
      });
    }
    if (desired.disableDeviceAuth !== state.controlUiConfig.disableDeviceAuth) {
      updates.push({
        path: "gateway.controlUi.disableDeviceAuth",
        value: desired.disableDeviceAuth,
      });
    }

    if (!updates.length) {
      setControlUiSettingsStatus("No control UI setting changes to save.", false);
      return;
    }

    setBusy(true);
    try {
      for (const update of updates) {
        const body = { path: update.path, value: update.value };
        if (state.configHash) {
          body.baseHash = state.configHash;
        }
        const response = await controlPatch("/control/config", body);
        if (typeof response.hash === "string") {
          state.configHash = response.hash;
        }
      }
      await refreshAll();
      setControlUiSettingsStatus(`Saved ${updates.length} control UI setting(s).`, false);
    } catch (err) {
      setControlUiSettingsStatus(String(err), true);
    } finally {
      setBusy(false);
    }
  }

  async function startGeminiOauth() {
    const payload = {};
    const origin = window.location.origin;
    if (origin && (origin.startsWith("http://") || origin.startsWith("https://"))) {
      payload.redirectBaseUrl = origin;
    }
    const clientId = ui.geminiClientIdInput.value.trim();
    const clientSecret = ui.geminiClientSecretInput.value.trim();
    if (clientId) {
      payload.clientId = clientId;
    }
    if (clientSecret) {
      payload.clientSecret = clientSecret;
    }
    ui.geminiClientSecretInput.value = "";

    let authWindow = null;
    try {
      authWindow = window.open("about:blank", "_blank", "noopener,noreferrer");
    } catch (e) {
      authWindow = null;
    }

    setBusy(true);
    try {
      const response = await controlPost("/control/onboarding/gemini/oauth/start", payload);
      state.geminiFlowId = response.flowId || null;
      renderGeminiOnboardingForm();
      if (!response.authUrl) {
        if (authWindow && !authWindow.closed) {
          authWindow.close();
        }
        throw new Error("Gemini Google sign-in did not return an authorization URL.");
      }

      let popupOpened = false;
      if (authWindow && !authWindow.closed) {
        authWindow.location.href = response.authUrl;
        popupOpened = true;
      } else {
        try {
          popupOpened = Boolean(window.open(response.authUrl, "_blank", "noopener,noreferrer"));
        } catch (e) {
          popupOpened = false;
        }
      }

      if (popupOpened) {
        setGeminiOnboardingStatus("Opened Google sign-in in a new tab. Return here after authorizing.", false);
      } else {
        setGeminiOnboardingStatus(
          `Popup blocked. Open this URL manually to continue Gemini Google sign-in: ${response.authUrl}`,
          true
        );
      }
    } catch (err) {
      if (authWindow && !authWindow.closed) {
        authWindow.close();
      }
      setGeminiOnboardingStatus(String(err), true);
    } finally {
      setBusy(false);
    }
  }

  async function refreshGeminiOauthStatus() {
    if (!state.geminiFlowId) {
      setGeminiOnboardingStatus("Start Google sign-in first.", true);
      return;
    }

    setBusy(true);
    try {
      const response = await controlGet(
        `/control/onboarding/gemini/oauth/${encodeURIComponent(state.geminiFlowId)}`
      );
      const status = response && response.status ? response.status : {};
      const stateText = String(status.status || "unknown");
      if (stateText === "completed") {
        setGeminiOnboardingStatus(
          `Google sign-in completed${status.email ? ` for ${status.email}` : ""}. Click Apply Google sign-in.`,
          false
        );
      } else if (stateText === "failed") {
        setGeminiOnboardingStatus(String(status.error || "Gemini Google sign-in failed."), true);
      } else {
        setGeminiOnboardingStatus("Google sign-in is still pending.", false);
      }
    } catch (err) {
      setGeminiOnboardingStatus(String(err), true);
    } finally {
      setBusy(false);
    }
  }

  async function applyGeminiOauth() {
    if (!state.geminiFlowId) {
      setGeminiOnboardingStatus("Start Google sign-in first.", true);
      return;
    }

    setBusy(true);
    try {
      const response = await controlPost(
        `/control/onboarding/gemini/oauth/${encodeURIComponent(state.geminiFlowId)}/apply`,
        {}
      );
      if (typeof response.hash === "string") {
        state.configHash = response.hash;
      }
      state.geminiFlowId = null;
      await refreshAll();
      setGeminiOnboardingStatus("Gemini Google sign-in applied.", false);
    } catch (err) {
      setGeminiOnboardingStatus(String(err), true);
    } finally {
      setBusy(false);
      renderGeminiOnboardingForm();
    }
  }

  async function saveGeminiApiKey() {
    const apiKey = ui.geminiApiKeyInput.value.trim();
    if (!apiKey) {
      setGeminiOnboardingStatus("Gemini API key is required.", true);
      return;
    }

    setBusy(true);
    try {
      const response = await controlPost("/control/onboarding/gemini/api-key", {
        apiKey,
        baseUrl: ui.geminiBaseUrlInput.value.trim(),
      });
      if (typeof response.hash === "string") {
        state.configHash = response.hash;
      }
      state.geminiFlowId = null;
      ui.geminiApiKeyInput.value = "";
      await refreshAll();
      setGeminiOnboardingStatus("Gemini API key saved.", false);
    } catch (err) {
      setGeminiOnboardingStatus(String(err), true);
    } finally {
      setBusy(false);
      renderGeminiOnboardingForm();
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

      const response = await controlPatch("/control/config", body);
      renderJson(ui.configJson, response);
      if (typeof response.hash === "string") {
        state.configHash = response.hash;
      }

      await refreshAll();
      setConfigStatus("Config patch applied.", false);
    } catch (err) {
      setConfigStatus(String(err), true);
    } finally {
      setBusy(false);
    }
  }

  async function refreshTasks(quiet) {
    const stateFilter = ui.taskFilterState.value.trim();
    const path = stateFilter ? `/control/tasks?state=${encodeURIComponent(stateFilter)}` : "/control/tasks";
    const payload = await controlGet(path);
    state.tasks = Array.isArray(payload.tasks) ? payload.tasks : [];
    if (!state.selectedTaskId || !state.tasks.some((task) => task && task.id === state.selectedTaskId)) {
      state.selectedTaskId = state.tasks.length ? String(state.tasks[0].id || "") : null;
    }
    renderTaskCards();
    await loadSelectedTask();
    if (!quiet) {
      setTaskStatus(`Loaded ${state.tasks.length} task(s).`, false);
    }
  }

  function clearNode(target) {
    while (target.firstChild) {
      target.removeChild(target.firstChild);
    }
  }

  function appendDetailLine(card, text, extraClass) {
    const detail = document.createElement("div");
    detail.className = extraClass ? `detail ${extraClass}` : "detail";
    detail.textContent = text;
    card.appendChild(detail);
  }

  function appendMessageCard(target, message) {
    clearNode(target);
    const card = document.createElement("div");
    card.className = "card";
    appendDetailLine(card, message);
    target.appendChild(card);
  }

  function renderTaskCards() {
    if (!state.tasks.length) {
      appendMessageCard(ui.tasksCards, "No tasks found.");
      return;
    }

    clearNode(ui.tasksCards);

    for (const task of state.tasks) {
      const id = String(task && task.id ? task.id : "unknown");
      const selected = state.selectedTaskId && String(task.id) === state.selectedTaskId;
      const taskState = String(task && task.state ? task.state : "unknown");
      const attempts = Number(task && task.attempts ? task.attempts : 0);
      const maxAttempts = Number(dig(task, ["policy", "maxAttempts"]) || 0);
      const nextRun = formatEpochMillis(task && task.nextRunAtMs);
      const updatedAt = formatEpochMillis(task && task.updatedAtMs);

      const card = document.createElement("article");
      card.className = selected ? "card selected" : "card";

      const title = document.createElement("div");
      title.className = "title";
      title.textContent = id;
      card.appendChild(title);

      appendDetailLine(card, `state: ${taskState}`);
      appendDetailLine(card, `attempts: ${attempts}${maxAttempts ? ` / ${maxAttempts}` : ""}`);
      appendDetailLine(card, `next run: ${nextRun}`);
      appendDetailLine(card, `updated: ${updatedAt}`);

      const row = document.createElement("div");
      row.className = "row";
      const selectButton = document.createElement("button");
      selectButton.className = "secondary";
      selectButton.dataset.taskId = id;
      selectButton.textContent = "Select";
      row.appendChild(selectButton);
      card.appendChild(row);

      ui.tasksCards.appendChild(card);
    }
  }

  async function selectTask(taskId) {
    state.selectedTaskId = taskId;
    renderTaskCards();
    await loadSelectedTask();
  }

  async function loadSelectedTask() {
    if (!state.selectedTaskId) {
      state.selectedTask = null;
      renderJson(ui.taskDetailJson, {});
      updateTaskActionButtons();
      return;
    }

    try {
      const payload = await controlGet(`/control/tasks/${encodeURIComponent(state.selectedTaskId)}`);
      state.selectedTask = payload && payload.task ? payload.task : null;
      renderJson(ui.taskDetailJson, state.selectedTask || {});
      updateTaskActionButtons();
    } catch (err) {
      state.selectedTask = null;
      renderJson(ui.taskDetailJson, {});
      updateTaskActionButtons();
      setTaskStatus(String(err), true);
    }
  }

  async function cancelSelectedTask() {
    const taskId = selectedTaskIdOrReport();
    if (!taskId) {
      return;
    }
    const body = {};
    const reason = ui.taskActionReasonInput.value.trim();
    if (reason) {
      body.reason = reason;
    }

    await runTaskMutation("Cancelled task.", async () => controlPost(`/control/tasks/${taskId}/cancel`, body));
  }

  async function retrySelectedTask() {
    const taskId = selectedTaskIdOrReport();
    if (!taskId) {
      return;
    }
    const body = {};
    const reason = ui.taskActionReasonInput.value.trim();
    if (reason) {
      body.reason = reason;
    }
    let delayMs;
    try {
      delayMs = parseOptionalNonNegativeInt(ui.taskActionDelayMsInput.value, "delayMs");
    } catch (err) {
      setTaskStatus(String(err), true);
      return;
    }
    if (delayMs !== null) {
      body.delayMs = delayMs;
    }

    await runTaskMutation("Retried task.", async () => controlPost(`/control/tasks/${taskId}/retry`, body));
  }

  async function resumeSelectedTask() {
    const taskId = selectedTaskIdOrReport();
    if (!taskId) {
      return;
    }
    const body = {};
    const reason = ui.taskActionReasonInput.value.trim();
    if (reason) {
      body.reason = reason;
    }
    let delayMs;
    try {
      delayMs = parseOptionalNonNegativeInt(ui.taskActionDelayMsInput.value, "delayMs");
    } catch (err) {
      setTaskStatus(String(err), true);
      return;
    }
    if (delayMs !== null) {
      body.delayMs = delayMs;
    }

    await runTaskMutation("Resumed blocked task.", async () => controlPost(`/control/tasks/${taskId}/resume`, body));
  }

  async function patchSelectedTask() {
    const taskId = selectedTaskIdOrReport();
    if (!taskId) {
      return;
    }

    const body = {};
    const reason = ui.taskActionReasonInput.value.trim();
    if (reason) {
      body.reason = reason;
    }

    const payloadText = ui.taskPatchPayloadInput.value.trim();
    if (payloadText) {
      try {
        body.payload = JSON.parse(payloadText);
      } catch (err) {
        setTaskStatus(`Patch payload must be valid JSON: ${err}`, true);
        return;
      }
    }

    const policy = {};
    let maxAttempts;
    let maxTotalRuntimeMs;
    let maxTurns;
    let maxRunTimeoutSeconds;
    try {
      maxAttempts = parseOptionalPositiveInt(ui.taskPatchMaxAttemptsInput.value, "policy.maxAttempts");
      maxTotalRuntimeMs = parseOptionalPositiveInt(
        ui.taskPatchMaxTotalRuntimeMsInput.value,
        "policy.maxTotalRuntimeMs"
      );
      maxTurns = parseOptionalPositiveInt(ui.taskPatchMaxTurnsInput.value, "policy.maxTurns");
      maxRunTimeoutSeconds = parseOptionalPositiveInt(
        ui.taskPatchMaxRunTimeoutSecondsInput.value,
        "policy.maxRunTimeoutSeconds"
      );
    } catch (err) {
      setTaskStatus(String(err), true);
      return;
    }
    if (maxAttempts !== null) {
      policy.maxAttempts = maxAttempts;
    }
    if (maxTotalRuntimeMs !== null) {
      policy.maxTotalRuntimeMs = maxTotalRuntimeMs;
    }
    if (maxTurns !== null) {
      policy.maxTurns = maxTurns;
    }
    if (maxRunTimeoutSeconds !== null) {
      policy.maxRunTimeoutSeconds = maxRunTimeoutSeconds;
    }
    if (Object.keys(policy).length > 0) {
      body.policy = policy;
    }

    if (!("payload" in body) && !("policy" in body) && !("reason" in body)) {
      setTaskStatus("Patch requires payload JSON, policy field(s), or reason.", true);
      return;
    }

    await runTaskMutation("Patched task.", async () => controlPatch(`/control/tasks/${taskId}`, body));
  }

  async function runTaskMutation(successMessage, operation) {
    setBusy(true);
    try {
      const response = await operation();
      if (response && response.task && response.task.id) {
        state.selectedTaskId = String(response.task.id);
      }
      await refreshTasks(true);
      setTaskStatus(successMessage, false);
    } catch (err) {
      setTaskStatus(String(err), true);
    } finally {
      setBusy(false);
    }
  }

  function selectedTaskIdOrReport() {
    const taskId = state.selectedTaskId;
    if (!taskId) {
      setTaskStatus("Select a task first.", true);
      return null;
    }
    return encodeURIComponent(taskId);
  }

  function updateTaskActionButtons() {
    const task = state.selectedTask;
    const selected = Boolean(task && task.id);
    const taskState = selected ? String(task.state || "") : "";
    const retryable = selected && !["queued", "running", "done"].includes(taskState);
    const resumable = selected && taskState === "blocked";
    const cancellable = selected && !["failed", "done", "cancelled"].includes(taskState);
    const patchable = selected && !["running", "done"].includes(taskState);

    ui.taskCancelButton.disabled = state.isBusy || !cancellable;
    ui.taskRetryButton.disabled = state.isBusy || !retryable;
    ui.taskResumeButton.disabled = state.isBusy || !resumable;
    ui.taskApplyPatchButton.disabled = state.isBusy || !patchable;
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
        version: "0.2.0",
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

  async function controlPatch(path, body) {
    const response = await fetch(path, {
      method: "PATCH",
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
    const headers = {};

    const credential = currentCredential();
    if (credential) {
      headers.Authorization = `Bearer ${credential}`;
    }

    const csrfHeader = csrfHeaderName;
    if (csrfHeader) {
      const csrfToken = csrfCookieName ? readCookie(csrfCookieName) : "";
      if (csrfToken) {
        headers[csrfHeader] = csrfToken;
      }
    }

    return headers;
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
      appendMessageCard(ui.channelsCards, "No channels configured.");
      return;
    }

    clearNode(ui.channelsCards);
    for (const channel of channels) {
      const name = String(channel && (channel.name || channel.id) ? channel.name || channel.id : "unknown");
      const status = String(channel && channel.status ? channel.status : "unknown");
      const connectedAt = channel && channel.lastConnectedAt ? String(channel.lastConnectedAt) : "-";
      const error = channel && channel.lastError ? String(channel.lastError) : "";

      const card = document.createElement("article");
      card.className = "card";

      const title = document.createElement("div");
      title.className = "title";
      title.textContent = name;
      card.appendChild(title);

      appendDetailLine(card, `status: ${status}`);
      appendDetailLine(card, `last connected: ${connectedAt}`);
      if (error) {
        appendDetailLine(card, error, "error");
      }

      ui.channelsCards.appendChild(card);
    }
  }

  function renderPairingLists(payload) {
    const pending = Array.isArray(payload && payload.pending) ? payload.pending : [];
    const paired = Array.isArray(payload && payload.paired) ? payload.paired : [];

    if (!pending.length) {
      appendMessageCard(ui.pendingPairings, "No pending pairing requests.");
    } else {
      clearNode(ui.pendingPairings);
      for (const item of pending) {
        const requestId = String(item && item.requestId ? item.requestId : "");
        const deviceId = String(item && item.deviceId ? item.deviceId : "unknown");
        const displayName = String(item && item.displayName ? item.displayName : "(no display name)");
        const remoteIp = String(item && item.remoteIp ? item.remoteIp : "local");

        const card = document.createElement("article");
        card.className = "card";

        const title = document.createElement("div");
        title.className = "title";
        title.textContent = displayName;
        card.appendChild(title);

        appendDetailLine(card, `requestId: ${requestId}`);
        appendDetailLine(card, `deviceId: ${deviceId}`);
        appendDetailLine(card, `remoteIp: ${remoteIp}`);

        const row = document.createElement("div");
        row.className = "row";
        const approve = document.createElement("button");
        approve.dataset.action = "approve";
        approve.dataset.requestId = requestId;
        approve.textContent = "Approve";
        const reject = document.createElement("button");
        reject.className = "danger";
        reject.dataset.action = "reject";
        reject.dataset.requestId = requestId;
        reject.textContent = "Reject";
        row.appendChild(approve);
        row.appendChild(reject);
        card.appendChild(row);

        ui.pendingPairings.appendChild(card);
      }
    }

    if (!paired.length) {
      appendMessageCard(ui.pairedDevices, "No paired devices.");
      return;
    }

    clearNode(ui.pairedDevices);
    for (const item of paired) {
      const deviceId = String(item && item.deviceId ? item.deviceId : "unknown");
      const displayName = String(item && item.displayName ? item.displayName : "(no display name)");
      const platform = String(item && item.platform ? item.platform : "unknown");
      const lastSeen = item && item.lastSeenAtMs ? new Date(Number(item.lastSeenAtMs)).toISOString() : "-";

      const card = document.createElement("article");
      card.className = "card";

      const title = document.createElement("div");
      title.className = "title";
      title.textContent = displayName;
      card.appendChild(title);

      appendDetailLine(card, `deviceId: ${deviceId}`);
      appendDetailLine(card, `platform: ${platform}`);
      appendDetailLine(card, `lastSeen: ${lastSeen}`);

      ui.pairedDevices.appendChild(card);
    }
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
    sessionStorage.removeItem("carapace.control.authType");
    setAuthStatus("Credential cleared.", false);
    disconnectPairingSocket();

    state.tasks = [];
    state.selectedTaskId = null;
    state.selectedTask = null;
    appendMessageCard(ui.tasksCards, "No tasks loaded.");
    renderJson(ui.taskDetailJson, {});
    updateTaskActionButtons();
  }

  function onToggleAuthVisibility() {
    const nextType = ui.authInput.type === "password" ? "text" : "password";
    ui.authInput.type = nextType;
    ui.toggleAuthVisibilityButton.textContent = nextType === "password" ? "Show" : "Hide";
  }

  function setBusy(busy) {
    state.isBusy = Boolean(busy);

    ui.refreshAllButton.disabled = state.isBusy;
    ui.applyConfigButton.disabled = state.isBusy;
    ui.saveAuthButton.disabled = state.isBusy;
    ui.clearAuthButton.disabled = state.isBusy;
    ui.saveControlUiSettingsButton.disabled = state.isBusy;
    ui.geminiAuthModeSelect.disabled = state.isBusy;
    ui.geminiStartOauthButton.disabled = state.isBusy;
    ui.geminiSaveApiKeyButton.disabled = state.isBusy;
    ui.refreshTasksButton.disabled = state.isBusy;

    ui.wsConnectButton.disabled = state.isBusy || (state.ws && state.ws.readyState === WebSocket.OPEN);
    ui.wsDisconnectButton.disabled = state.isBusy || !(state.ws && state.ws.readyState === WebSocket.OPEN);
    ui.wsRefreshPairingsButton.disabled =
      state.isBusy || !(state.ws && state.ws.readyState === WebSocket.OPEN && state.wsAuthed);

    updateTaskActionButtons();
    renderGeminiOnboardingForm();
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

  function setControlUiSettingsStatus(message, isError) {
    ui.controlUiSettingsStatus.textContent = message;
    ui.controlUiSettingsStatus.classList.toggle("error", Boolean(isError));
    ui.controlUiSettingsStatus.classList.toggle("success", !isError);
  }

  function setGeminiOnboardingStatus(message, isError) {
    ui.geminiOnboardingStatus.textContent = message;
    ui.geminiOnboardingStatus.classList.toggle("error", Boolean(isError));
    ui.geminiOnboardingStatus.classList.toggle("success", !isError);
  }

  function setPairingStatus(message, isError) {
    ui.pairingStatus.textContent = message;
    ui.pairingStatus.classList.toggle("error", Boolean(isError));
    ui.pairingStatus.classList.toggle("success", !isError);
  }

  function setTaskStatus(message, isError) {
    ui.taskStatus.textContent = message;
    ui.taskStatus.classList.toggle("error", Boolean(isError));
    ui.taskStatus.classList.toggle("success", !isError);
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

    ui.wsConnectButton.disabled = state.isBusy || open;
    ui.wsDisconnectButton.disabled = state.isBusy || !open;
    ui.wsRefreshPairingsButton.disabled = state.isBusy || !ready;
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

  function loadRuntimeConfig() {
    const basePath = readBootstrapMeta("carapace-control-ui-base-path", "__CARAPACE_CONTROL_UI_BASE_PATH__");
    const assistantName = readBootstrapMeta("carapace-assistant-name", "__CARAPACE_ASSISTANT_NAME__");
    const assistantAvatar = readBootstrapMeta("carapace-assistant-avatar", "__CARAPACE_ASSISTANT_AVATAR__");
    const csrfCookieName = readBootstrapMeta("carapace-csrf-cookie", "__CARAPACE_CSRF_COOKIE__");
    const csrfHeaderName = readBootstrapMeta("carapace-csrf-header", "__CARAPACE_CSRF_HEADER__");

    return {
      basePath,
      assistantName,
      assistantAvatar,
      csrfCookieName,
      csrfHeaderName,
    };
  }

  function readBootstrapMeta(name, placeholder) {
    const content = document.querySelector(`meta[name="${name}"]`)?.getAttribute("content") || "";
    const trimmed = content.trim();
    if (!trimmed || trimmed === placeholder) {
      return "";
    }
    return trimmed;
  }

  function readCookie(name) {
    const raw = document.cookie || "";
    const parts = raw.split(";");
    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed.startsWith(`${name}=`)) {
        return trimmed.slice(name.length + 1);
      }
    }
    return "";
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

  function parseOptionalNonNegativeInt(raw, fieldName) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) {
      return null;
    }
    const parsed = Number(trimmed);
    if (!Number.isInteger(parsed) || parsed < 0) {
      throw new Error(`${fieldName} must be a non-negative integer`);
    }
    return parsed;
  }

  function parseOptionalPositiveInt(raw, fieldName) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) {
      return null;
    }
    const parsed = Number(trimmed);
    if (!Number.isInteger(parsed) || parsed < 1) {
      throw new Error(`${fieldName} must be an integer >= 1`);
    }
    return parsed;
  }

  function formatEpochMillis(value) {
    if (value === null || value === undefined) {
      return "-";
    }
    const millis = Number(value);
    if (!Number.isFinite(millis) || millis <= 0) {
      return "-";
    }
    try {
      return new Date(millis).toISOString();
    } catch (_err) {
      return "-";
    }
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

  function noop() {
    // Explicit no-op for background Promise chains.
  }
})();
