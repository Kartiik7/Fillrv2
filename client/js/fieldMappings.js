/**
 * fieldMappings.js — Admin Field Mapping Editor
 *
 * Keyword categories (matching DB schema):
 *  primary   — high-confidence labels (≥1 required)
 *  secondary — moderate-confidence patterns
 *  generic   — low-specificity fallback terms
 *  negative  — terms that DISQUALIFY this field
 *
 * Security:
 *  - All user input escaped with escHtml() / escAttr() before DOM insertion
 *  - No eval(), no innerHTML from raw user data, no dynamic script injection
 *  - JWT sent as Bearer header only — never embedded in HTML or logs
 *  - 401 → redirect to login; 403 → access-denied UI; 5xx → safe error message
 *  - No MongoDB _id ever displayed (uses 'key' as the client-side identifier)
 *  - Role, suspension state, etc. never settable from this page
 *
 * Functions:
 *  - fetchMappings()     Loads from GET /api/admin/field-mappings
 *  - renderTable()       Renders (with optional search filter)
 *  - openModal(mapping)  Opens create (null) or edit (mapping) modal
 *  - validateMapping()   Client-side validation, returns errors object
 *  - saveMapping()       POST to backend (upsert); server logs audit trail
 *  - deleteMapping(key)  Opens confirm modal → DELETE on confirm
 */

'use strict';

/* ── Config ────────────────────────────────────────────────── */
const API       = (typeof ENV !== 'undefined' && ENV.API_URL) ? ENV.API_URL : 'http://localhost:5000/api';
const TOKEN_KEY = 'fillr_token';
const FM_CHANGE_KEY = 'fillr:fm-last-change';

const GROUP_DEFS = [
  { key: 'identity',  label: 'Identity',  prefix: 'ids.' },
  { key: 'personal',  label: 'Personal',  prefix: 'personal.' },
  { key: 'academics', label: 'Academics', prefix: 'academics.' },
  { key: 'education', label: 'Education', prefix: 'education.' },
  { key: 'placement', label: 'Placement', prefix: 'placement.' },
  { key: 'links',     label: 'Links',     prefix: 'links.' },
];

/* ── Auth Gate (redirect before any DOM manipulation) ─────── */
const token = localStorage.getItem(TOKEN_KEY);
if (!token) window.location.replace('/login');

/* ── State ─────────────────────────────────────────────────── */
let _mappings      = [];    // in-memory source of truth
let _kw            = { primary: [], secondary: [], generic: [], negative: [] };  // tags for modal currently open
let _editingKey    = null;  // null = create; string = edit key
let _pendingDelKey = null;  // key awaiting confirmed delete
let _isFetching    = false;
let _isSaving      = false;
let _isDeleting    = false;
let _searchQuery   = '';

// Per-category config: max entries allowed
const KW_MAX = { primary: 30, secondary: 20, generic: 10, negative: 20 };
const CATEGORIES = ['primary', 'secondary', 'generic', 'negative'];

/* ── DOM Refs ──────────────────────────────────────────────── */
const $ = (id) => document.getElementById(id);

const dom = {
  mainContent:    $('mainContent'),
  accessDenied:   $('accessDenied'),
  errorBanner:    $('errorBanner'),
  // Toast
  toast:          $('toast'),
  toastIcon:      $('toastIcon'),
  toastMsg:       $('toastMsg'),
  // Header
  refreshBtn:     $('refreshBtn'),
  refreshIcon:    $('refreshIcon'),
  addBtn:         $('addBtn'),
  signoutBtn:     $('signoutBtn'),
  configVersion:  $('configVersion'),
  // Stats
  totalCountVal:  $('totalCountVal'),
  lastUpdatedVal: $('lastUpdatedVal'),
  // Recent mappings
  recentList:     $('recentMappingsList'),
  recentCount:    $('recentMappingsCount'),
  // Search
  searchInput:    $('searchInput'),
  searchClear:    $('searchClear'),
  // Table
  tableLoading:   $('tableLoading'),
  fmTable:        $('fmTable'),
  fmBody:         $('fmBody'),
  emptyState:     $('emptyState'),
  noResults:      $('noResults'),
  // Mapping modal
  mappingModal:   $('mappingModal'),
  modalTitle:     $('modalTitle'),
  modalClose:     $('modalClose'),
  modalCancel:    $('modalCancel'),
  mappingForm:    $('mappingForm'),
  inputKey:       $('inputKey'),
  inputPath:      $('inputPath'),
    inputFieldType: $('inputFieldType'),
  saveBtn:        $('saveBtn'),
  saveBtnLabel:   $('saveBtnLabel'),
  keyCount:       $('keyCount'),
  keyError:       $('keyError'),
  pathError:      $('pathError'),
  // Delete confirm modal
  confirmModal:      $('confirmModal'),
  confirmClose:      $('confirmClose'),
  confirmCancel:     $('confirmCancel'),
  confirmDeleteBtn:  $('confirmDeleteBtn'),
  confirmKeyLabel:   $('confirmKeyLabel'),
  confirmBtnLabel:   $('confirmBtnLabel'),
};

// Per-category DOM refs
const kwDom = {
  primary:   { input: $('inputPrimary'),   tags: $('tagsWrapPrimary'),   count: $('primaryCount'),   error: $('primaryError')   },
  secondary: { input: $('inputSecondary'), tags: $('tagsWrapSecondary'), count: $('secondaryCount'), error: $('secondaryError') },
  generic:   { input: $('inputGeneric'),   tags: $('tagsWrapGeneric'),   count: $('genericCount'),   error: $('genericError')   },
  negative:  { input: $('inputNegative'),  tags: $('tagsWrapNegative'),  count: $('negativeCount'),  error: $('negativeError')  },
};

/* ════════════════════════════════════════════════════════════ *
 *  SECURITY HELPERS                                            *
 * ════════════════════════════════════════════════════════════ */

/** Escape HTML to prevent XSS in innerHTML template literals */
function escHtml(value) {
  const s = String(value == null ? '' : value);
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

/** Escape a value for use inside an HTML attribute (double-quoted) */
function escAttr(str) {
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/"/g,  '&quot;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;');
}

/* ════════════════════════════════════════════════════════════ *
 *  API FETCH WRAPPER                                           *
 * ════════════════════════════════════════════════════════════ */

/**
 * JWT-authenticated fetch with 401/403 handling.
 * Never exposes raw stack traces or server internals to the UI.
 */
async function apiFetch(path, opts = {}) {
  const headers = {
    'Content-Type': 'application/json',
    Authorization:  `Bearer ${token}`,
    ...opts.headers,
  };
  const res = await fetch(`${API}${path}`, { ...opts, headers });

  if (res.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.replace('/login');
    throw new Error('UNAUTHORIZED');
  }
  if (res.status === 403) {
    showAccessDenied();
    throw new Error('FORBIDDEN');
  }

  const body = await res.json().catch(() => ({
    success: false,
    message: `Request failed (${res.status})`,
  }));

  if (!res.ok) {
    throw new Error(body.message || `Request failed (${res.status})`);
  }
  return body;
}

/* ════════════════════════════════════════════════════════════ *
 *  DATA LAYER                                                  *
 * ════════════════════════════════════════════════════════════ */

/** Fetch all field mappings; update state and re-render. */
async function fetchMappings({ highlightKey } = {}) {
  if (_isFetching) return;
  _isFetching = true;
  setRefreshing(true);
  showTableLoading();

  try {
    const data = await apiFetch('/admin/field-mappings');
    // Normalise arrays client-side too — guards against any older server version
    _mappings = (Array.isArray(data.mappings) ? data.mappings : []).map(m => ({
      key:       m.key,
      path:      m.path,
      fieldType: m.fieldType || 'text',
      primary:   Array.isArray(m.primary)   ? m.primary   : [],
      secondary: Array.isArray(m.secondary) ? m.secondary : [],
      generic:   Array.isArray(m.generic)   ? m.generic   : [],
      negative:  Array.isArray(m.negative)  ? m.negative  : [],
      updatedAt: m.updatedAt,
    }));
    renderTable(highlightKey);
    updateStats();
    renderRecentMappings();
    fetchConfigVersion(); // non-critical; fire-and-forget
  } catch (err) {
    if (err.message !== 'UNAUTHORIZED' && err.message !== 'FORBIDDEN') {
      showTableError('Failed to load field mappings. Check your connection.');
    }
  } finally {
    setRefreshing(false);
    _isFetching = false;
  }
}

/** Silently fetch config version number (non-blocking). */
async function fetchConfigVersion() {
  try {
    const data = await fetch(`${API}/config/version`).then(r => r.json());
    if (data.version != null) {
      dom.configVersion.textContent = `v${data.version}`;
    }
  } catch (_) { /* non-critical */ }
}

function sortMappingsByUpdatedDesc(list = _mappings) {
  return [...list].sort((a, b) => {
    const ta = a.updatedAt ? new Date(a.updatedAt).getTime() : 0;
    const tb = b.updatedAt ? new Date(b.updatedAt).getTime() : 0;
    if (tb === ta) return a.key.localeCompare(b.key);
    return tb - ta;
  });
}

function getLatestUpdatedAt() {
  const sorted = sortMappingsByUpdatedDesc();
  return sorted.length > 0 ? sorted[0].updatedAt || null : null;
}

function getGroupMeta(path) {
  const p = String(path || '').toLowerCase();
  const found = GROUP_DEFS.find(g => p.startsWith(g.prefix));
  return found || { key: 'other', label: 'Other' };
}

/* ════════════════════════════════════════════════════════════ *
 *  RENDERING                                                   *
 * ════════════════════════════════════════════════════════════ */

/**
 * Render (or re-render) the mappings table.
 * Applies _searchQuery filter. Highlights row if highlightKey provided.
 * @param {string} [highlightKey] - key of row to animate as new/modified
 */
function renderTable(highlightKey) {
  hideTableLoading();

  const query    = _searchQuery.toLowerCase();
  const filtered = query
    ? _mappings.filter(m => {
        if (m.key.toLowerCase().includes(query))  return true;
        if (m.path.toLowerCase().includes(query)) return true;
        const allKw = [...(m.primary||[]), ...(m.secondary||[]), ...(m.generic||[]), ...(m.negative||[])];
        return allKw.some(k => k.toLowerCase().includes(query));
      })
    : _mappings;

  if (_mappings.length === 0) {
    dom.fmTable.hidden   = true;
    dom.emptyState.hidden = false;
    dom.noResults.hidden  = true;
    return;
  }

  if (filtered.length === 0) {
    dom.fmTable.hidden    = true;
    dom.emptyState.hidden = true;
    dom.noResults.hidden  = false;
    return;
  }

  dom.emptyState.hidden = true;
  dom.noResults.hidden  = true;
  dom.fmTable.hidden    = false;

  const groupBuckets = new Map();
  GROUP_DEFS.forEach(g => groupBuckets.set(g.key, { label: g.label, items: [] }));
  groupBuckets.set('other', { label: 'Other', items: [] });

  filtered.forEach(m => {
    const group = getGroupMeta(m.path);
    const bucket = groupBuckets.get(group.key) || groupBuckets.get('other');
    bucket.items.push(m);
  });

  const renderRow = (m) => {
    const primary   = m.primary   || [];
    const secondary = m.secondary || [];
    const generic   = m.generic   || [];
    const negative  = m.negative  || [];

    const priVisible  = primary.slice(0, 4);
    const priOverflow = primary.length - priVisible.length;
    const priTags = priVisible
      .map(kw => `<span class="adm-kw-tag adm-kw-tag-pri" title="${escAttr(kw)}">${escHtml(kw)}</span>`)
      .join('');
    const priMore = priOverflow > 0 ? `<span class="adm-kw-more">+${priOverflow}</span>` : '';

    const badges = [
      secondary.length > 0 ? `<span class="adm-kw-cat-badge adm-kwbadge-sec" title="${secondary.map(escAttr).join(', ')}">${secondary.length} sec</span>` : '',
      generic.length   > 0 ? `<span class="adm-kw-cat-badge adm-kwbadge-gen" title="${generic.map(escAttr).join(', ')}">${generic.length} gen</span>`     : '',
      negative.length  > 0 ? `<span class="adm-kw-cat-badge adm-kwbadge-neg" title="${negative.map(escAttr).join(', ')}">${negative.length} neg</span>`    : '',
    ].filter(Boolean).join('');

    const kwCell = (primary.length === 0 && !badges)
      ? '<span class="adm-kw-none">—</span>'
      : `<div class="adm-kw-tags">${priTags}${priMore}</div>${badges ? `<div class="adm-kw-badges">${badges}</div>` : ''}`;

    return `
      <tr data-key="${escAttr(m.key)}"${m.key === highlightKey ? ' class="is-new"' : ''}>
        <td class="adm-cell-key">${escHtml(m.key)}</td>
        <td class="adm-cell-path">${escHtml(m.path)}</td>
        <td class="adm-cell-type"><span class="adm-type-badge adm-type-${escAttr(m.fieldType || 'text')}">${escHtml(m.fieldType || 'text')}</span></td>
        <td class="adm-cell-kw">${kwCell}</td>
        <td class="adm-cell-time">${m.updatedAt ? formatTime(m.updatedAt) : '—'}</td>
        <td class="adm-cell-actions">
          <button class="adm-tbl-btn adm-tbl-btn-edit" data-action="edit" data-key="${escAttr(m.key)}" aria-label="Edit ${escAttr(m.key)}">Edit</button>
          <button class="adm-tbl-btn adm-tbl-btn-del"  data-action="delete" data-key="${escAttr(m.key)}" aria-label="Delete ${escAttr(m.key)}">Delete</button>
        </td>
      </tr>`;
  };

  const html = [];
  GROUP_DEFS.forEach(g => {
    const bucket = groupBuckets.get(g.key);
    if (!bucket || bucket.items.length === 0) return;
    html.push(`<tr class="fm-group-row"><td colspan="6">${escHtml(bucket.label)}</td></tr>`);
    bucket.items.forEach(m => html.push(renderRow(m)));
  });

  const otherBucket = groupBuckets.get('other');
  if (otherBucket && otherBucket.items.length > 0) {
    html.push(`<tr class="fm-group-row"><td colspan="6">${escHtml(otherBucket.label)}</td></tr>`);
    otherBucket.items.forEach(m => html.push(renderRow(m)));
  }

  dom.fmBody.innerHTML = html.join('');
}

function updateStats() {
  const total = _mappings.length;
  dom.totalCountVal.textContent  = total;
  const latest = getLatestUpdatedAt();
  dom.lastUpdatedVal.textContent = latest ? formatTime(latest) : '—';
}

function renderRecentMappings() {
  if (!dom.recentList || !dom.recentCount) return;

  const sorted = sortMappingsByUpdatedDesc();
  if (sorted.length === 0) {
    dom.recentList.innerHTML = '<div class="fm-recent-empty">No mappings yet.</div>';
    dom.recentCount.textContent = '0';
    return;
  }

  dom.recentCount.textContent = String(sorted.length);
  const recent = sorted.slice(0, 5);

  dom.recentList.innerHTML = recent.map(m => `
    <div class="fm-recent-item">
      <div class="fm-recent-meta">
        <div class="fm-recent-key">${escHtml(m.key)}</div>
        <div class="fm-recent-path">${escHtml(m.path)}</div>
      </div>
      <div class="fm-recent-time">${m.updatedAt ? formatTime(m.updatedAt) : '—'}</div>
    </div>
  `).join('');
}

/* ════════════════════════════════════════════════════════════ *
 *  MODAL MANAGEMENT                                            *
 * ════════════════════════════════════════════════════════════ */

/**
 * Open the create/edit modal.
 * @param {object|null} mapping - null = create; object = edit
 */
function openModal(mapping = null) {
  const isEdit = mapping !== null;
  _editingKey = isEdit ? mapping.key : null;

  // Populate keyword state for all 4 categories
  CATEGORIES.forEach(cat => {
    _kw[cat] = isEdit ? [...(mapping[cat] || [])] : [];
    kwDom[cat].input.value = '';
  });

  dom.modalTitle.textContent   = isEdit ? `Edit "${mapping.key}"` : 'Add Field Mapping';
  dom.saveBtnLabel.textContent = isEdit ? 'Save Changes' : 'Create Mapping';

  dom.inputKey.value       = isEdit ? mapping.key : '';
  dom.inputKey.readOnly    = isEdit;
  dom.inputPath.value      = isEdit ? mapping.path : '';
  dom.inputFieldType.value = isEdit ? (mapping.fieldType || 'text') : 'text';
  dom.keyCount.textContent = `${dom.inputKey.value.length} / 40`;

  CATEGORIES.forEach(renderTags);
  clearAllErrors();

  dom.mappingModal.classList.add('show');
  setTimeout(() => (isEdit ? dom.inputPath : dom.inputKey).focus(), 60);
}

function closeModal() {
  dom.mappingModal.classList.remove('show');
  _editingKey = null;
  CATEGORIES.forEach(cat => {
    _kw[cat] = [];
    kwDom[cat].input.value = '';
    renderTags(cat); // clear chips so :empty CSS hides the wrap
  });
  dom.mappingForm.reset();
  clearAllErrors();
}

function openConfirmModal(key) {
  _pendingDelKey = key;
  dom.confirmKeyLabel.textContent = key; // textContent — safe, no innerHTML
  dom.confirmModal.classList.add('show');
  dom.confirmDeleteBtn.focus();
}

function closeConfirmModal() {
  dom.confirmModal.classList.remove('show');
  _pendingDelKey = null;
}

/* ════════════════════════════════════════════════════════════ *
 *  KEYWORD TAG INPUT (per-category)                           *
 * ════════════════════════════════════════════════════════════ */

/** Re-render the tag chips for one category. */
function renderTags(cat) {
  const { tags, count } = kwDom[cat];
  const arr = _kw[cat];
  const max = KW_MAX[cat];

  tags.innerHTML = arr.map((kw, i) => `
    <span class="adm-tag-item adm-tag-${cat}" role="option" aria-label="${escAttr(kw)}">
      <span class="adm-tag-text">${escHtml(kw)}</span>
      <button type="button" class="adm-tag-remove" data-category="${cat}" data-index="${i}" aria-label="Remove ${escAttr(kw)}">✕</button>
    </span>
  `).join('');
  // Visibility handled by CSS: .adm-tags-wrap:empty { display: none }
  count.textContent = `${arr.length} / ${max}`;
  count.classList.toggle('warn', arr.length >= max - 2);
}

/** Flush a pending keyword from the input for a given category. */
function addKeywordFromInput(cat) {
  const d   = kwDom[cat];
  const max = KW_MAX[cat];
  const raw = d.input.value.trim().replace(/,+$/, '').trim();
  if (!raw) { d.input.value = ''; return; }

  const kw = raw.toLowerCase().replace(/\s+/g, ' ');

  if (kw.length > 100) {
    showFieldError(`${cat}Error`, 'Each keyword must be 100 characters or fewer.');
    return;
  }
  if (_kw[cat].length >= max) {
    showFieldError(`${cat}Error`, `Maximum ${max} ${cat} keywords allowed.`);
    return;
  }
  if (_kw[cat].includes(kw)) {
    d.input.value = '';
    return; // silently ignore duplicates
  }

  clearFieldError(`${cat}Error`);
  _kw[cat].push(kw);
  d.input.value = '';
  renderTags(cat);
}

function removeKeyword(cat, index) {
  _kw[cat].splice(index, 1);
  clearFieldError(`${cat}Error`);
  renderTags(cat);
}

/* ════════════════════════════════════════════════════════════ *
 *  VALIDATION                                                  *
 * ════════════════════════════════════════════════════════════ */

const KEY_RE  = /^[a-zA-Z0-9._-]+$/;
const PATH_RE = /^[a-zA-Z0-9._-]+$/;

function validateMapping() {
  const errors = {};
  const key  = dom.inputKey.value.trim();
  const path = dom.inputPath.value.trim();

  if (!_editingKey) {
    if (!key)                                    errors.key = 'Key is required.';
    else if (key.length > 40)                    errors.key = 'Key must be 40 characters or fewer.';
    else if (!KEY_RE.test(key))                  errors.key = 'Key must contain only letters, numbers, dots, underscores, or hyphens.';
    else if (_mappings.some(m => m.key === key)) errors.key = `A mapping for "${key}" already exists.`;
  }

  if (!path)                   errors.path = 'Path is required.';
  else if (path.length > 100)  errors.path = 'Path must be 100 characters or fewer.';
  else if (!PATH_RE.test(path)) errors.path = 'Path must contain only letters, numbers, dots, underscores, or hyphens.';

  // Only primary is required
  if (_kw.primary.length === 0)              errors.primary = 'At least one primary keyword is required.';
  else if (_kw.primary.length > KW_MAX.primary) errors.primary = `Maximum ${KW_MAX.primary} primary keywords allowed.`;

  CATEGORIES.slice(1).forEach(cat => {
    if (_kw[cat].length > KW_MAX[cat]) errors[cat] = `Maximum ${KW_MAX[cat]} ${cat} keywords allowed.`;
  });

  return { valid: Object.keys(errors).length === 0, errors };
}

/* ════════════════════════════════════════════════════════════ *
 *  SAVE MAPPING                                                *
 * ════════════════════════════════════════════════════════════ */

async function saveMapping() {
  if (_isSaving) return;
  const isEditOperation = Boolean(_editingKey);

  // Flush pending keywords from all category inputs
  CATEGORIES.forEach(cat => { if (kwDom[cat].input.value.trim()) addKeywordFromInput(cat); });

  const { valid, errors } = validateMapping();
  if (!valid) {
    if (errors.key)     { showFieldError('keyError',     errors.key);     dom.inputKey.focus();  return; }
    if (errors.path)    { showFieldError('pathError',    errors.path);    dom.inputPath.focus(); return; }
    if (errors.primary) { showFieldError('primaryError', errors.primary);                        return; }
    // Show any optional category error
    for (const cat of CATEGORIES.slice(1)) {
      if (errors[cat]) { showFieldError(`${cat}Error`, errors[cat]); return; }
    }
    return;
  }

  const payload = {
    key:       _editingKey || dom.inputKey.value.trim(),
    path:      dom.inputPath.value.trim(),
    fieldType: dom.inputFieldType.value || 'text',
    primary:   _kw.primary,
    secondary: _kw.secondary,
    generic:   _kw.generic,
    negative:  _kw.negative,
  };

  setSaving(true);
  _isSaving = true;
  try {
    await apiFetch('/admin/field-mappings', {
      method: 'POST',
      body:   JSON.stringify(payload),
    });
    const savedKey = payload.key;
    closeModal();

    // Re-fetch latest mappings and highlight the newly added/updated row.
    await fetchMappings({ highlightKey: savedKey });

    notifyMappingsChanged();

    showToast(
      isEditOperation ? 'Mapping updated successfully.' : 'Mapping added successfully.',
      'success'
    );
  } catch (err) {
    if (err.message !== 'UNAUTHORIZED' && err.message !== 'FORBIDDEN') {
      showToast(err.message || 'Failed to save mapping.', 'error');
    }
  } finally {
    setSaving(false);
    _isSaving = false;
  }
}

/* ════════════════════════════════════════════════════════════ *
 *  DELETE MAPPING                                              *
 * ════════════════════════════════════════════════════════════ */

function deleteMapping(key) {
  openConfirmModal(key);
}

async function confirmDelete() {
  if (_isDeleting) return;
  if (!_pendingDelKey) return;
  const key = _pendingDelKey;

  setConfirmDeleting(true);
  _isDeleting = true;
  try {
    await apiFetch(`/admin/field-mappings/${encodeURIComponent(key)}`, { method: 'DELETE' });
    closeConfirmModal();
    _mappings = _mappings.filter(m => m.key !== key);
    renderTable();
    updateStats();
    renderRecentMappings();
    notifyMappingsChanged();
    showToast('Mapping deleted.', 'success');
  } catch (err) {
    if (err.message !== 'UNAUTHORIZED' && err.message !== 'FORBIDDEN') {
      closeConfirmModal();
      showToast(err.message || 'Failed to delete mapping.', 'error');
    }
  } finally {
    setConfirmDeleting(false);
    _isDeleting = false;
  }
}

/* ════════════════════════════════════════════════════════════ *
 *  UI STATE HELPERS                                            *
 * ════════════════════════════════════════════════════════════ */

function setRefreshing(on) {
  dom.refreshBtn.disabled = on;
  dom.refreshBtn.classList.toggle('loading', on);
}

function setSaving(on) {
  dom.saveBtn.disabled     = on;
  dom.modalCancel.disabled = on;
  dom.saveBtn.classList.toggle('saving', on);
}

function setConfirmDeleting(on) {
  dom.confirmDeleteBtn.disabled = on;
  dom.confirmDeleteBtn.classList.toggle('saving', on);
  dom.confirmBtnLabel.textContent = on ? 'Deleting…' : 'Delete';
}

function showTableLoading() {
  dom.tableLoading.hidden  = false;
  dom.fmTable.hidden       = true;
  dom.emptyState.hidden    = true;
  dom.noResults.hidden     = true;
}

function hideTableLoading() {
  dom.tableLoading.hidden = true;
}

function showTableError(msg) {
  hideTableLoading();
  dom.fmTable.hidden       = true;
  dom.emptyState.hidden    = false;
  // Safe: textContent, not innerHTML
  dom.emptyState.querySelector('.adm-empty-title').textContent = msg;
}

function showAccessDenied() {
  dom.mainContent.hidden  = true;
  dom.accessDenied.hidden = false;
}

function showFieldError(id, msg) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.hidden = false;
  // Map error id to its associated input
  const catMatch = id.match(/^(primary|secondary|generic|negative)Error$/);
  if (catMatch) { kwDom[catMatch[1]].input.classList.add('is-error'); return; }
  const inputMap = { keyError: dom.inputKey, pathError: dom.inputPath };
  if (inputMap[id]) inputMap[id].classList.add('is-error');
}

function clearFieldError(id) {
  const el = $(id);
  if (!el) return;
  el.textContent = '';
  el.hidden = true;
  const catMatch = id.match(/^(primary|secondary|generic|negative)Error$/);
  if (catMatch) { kwDom[catMatch[1]].input.classList.remove('is-error'); return; }
  const inputMap = { keyError: dom.inputKey, pathError: dom.inputPath };
  if (inputMap[id]) inputMap[id].classList.remove('is-error');
}

function clearAllErrors() {
  ['keyError', 'pathError', 'primaryError', 'secondaryError', 'genericError', 'negativeError']
    .forEach(id => clearFieldError(id));
}

/* ════════════════════════════════════════════════════════════ *
 *  TOAST                                                       *
 * ════════════════════════════════════════════════════════════ */

let _toastTimer = null;

/**
 * Show a toast notification matching .db-toast style.
 * @param {string} message
 * @param {'success'|'error'|''} type
 * @param {number} [duration]
 */
function showToast(message, type = '', duration = 3500) {
  clearTimeout(_toastTimer);
  dom.toastMsg.textContent  = message; // safe: textContent
  dom.toastIcon.textContent = type === 'success' ? '✓' : type === 'error' ? '✕' : '';
  dom.toast.className       = `adm-toast${type ? ` toast-${type}` : ''}`;
  void dom.toast.offsetHeight; // reflow to restart animation
  dom.toast.classList.add('show');
  _toastTimer = setTimeout(() => dom.toast.classList.remove('show'), duration);
}

/* ════════════════════════════════════════════════════════════ *
 *  UTILITIES                                                   *
 * ════════════════════════════════════════════════════════════ */

function formatTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('en-US', {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', hour12: false,
    });
  } catch (_) { return '—'; }
}

function notifyMappingsChanged() {
  try {
    localStorage.setItem(FM_CHANGE_KEY, String(Date.now()));
  } catch (_) { /* non-blocking */ }
}

/* ════════════════════════════════════════════════════════════ *
 *  EVENT WIRING                                                *
 * ════════════════════════════════════════════════════════════ */

dom.refreshBtn.addEventListener('click', fetchMappings);
dom.addBtn.addEventListener('click', () => openModal(null));
dom.signoutBtn.addEventListener('click', () => {
  localStorage.removeItem(TOKEN_KEY);
  window.location.replace('/login');
});

// Table: Edit / Delete delegation
dom.fmBody.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const key    = btn.dataset.key;
  const action = btn.dataset.action;
  if (!key) return;
  if (action === 'edit') {
    const mapping = _mappings.find(m => m.key === key);
    if (mapping) openModal(mapping);
  } else if (action === 'delete') {
    deleteMapping(key);
  }
});

// Table: double-click any row/cell to open edit modal
dom.fmBody.addEventListener('dblclick', (e) => {
  // Ignore explicit action buttons; they already have click handlers
  if (e.target.closest('button')) return;

  const row = e.target.closest('tr[data-key]');
  if (!row) return;

  const key = row.dataset.key;
  if (!key) return;

  const mapping = _mappings.find((m) => m.key === key);
  if (mapping) openModal(mapping);
});

// Mapping modal
dom.modalClose.addEventListener('click',  closeModal);
dom.modalCancel.addEventListener('click', closeModal);
dom.mappingForm.addEventListener('submit', (e) => { e.preventDefault(); saveMapping(); });

// Key input live char count
dom.inputKey.addEventListener('input', () => {
  dom.keyCount.textContent = `${dom.inputKey.value.length} / 40`;
  clearFieldError('keyError');
});
dom.inputPath.addEventListener('input', () => clearFieldError('pathError'));

// Keyword inputs — wired for all 4 categories
CATEGORIES.forEach(cat => {
  const { input, tags } = kwDom[cat];

  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addKeywordFromInput(cat); }
    if (e.key === 'Backspace' && input.value === '' && _kw[cat].length > 0) {
      removeKeyword(cat, _kw[cat].length - 1);
    }
  });
  input.addEventListener('blur', () => {
    if (input.value.trim()) addKeywordFromInput(cat);
  });

  // Tag removal delegation per category
  tags.addEventListener('click', (e) => {
    const btn = e.target.closest('.adm-tag-remove');
    if (!btn) return;
    const index = parseInt(btn.dataset.index, 10);
    if (!isNaN(index)) removeKeyword(cat, index);
  });
});

// Confirm modal
dom.confirmClose.addEventListener('click',     closeConfirmModal);
dom.confirmCancel.addEventListener('click',    closeConfirmModal);
dom.confirmDeleteBtn.addEventListener('click', confirmDelete);

// Overlay click closes modals
dom.mappingModal.addEventListener('click',  (e) => { if (e.target === dom.mappingModal)  closeModal(); });
dom.confirmModal.addEventListener('click',  (e) => { if (e.target === dom.confirmModal)  closeConfirmModal(); });

// Escape key
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (dom.mappingModal.classList.contains('show'))  { closeModal(); return; }
  if (dom.confirmModal.classList.contains('show'))  { closeConfirmModal(); }
});

// Search
dom.searchInput.addEventListener('input', () => {
  _searchQuery = dom.searchInput.value;
  dom.searchClear.hidden = _searchQuery.length === 0;
  renderTable();
});
dom.searchClear.addEventListener('click', () => {
  dom.searchInput.value = '';
  _searchQuery = '';
  dom.searchClear.hidden = true;
  renderTable();
  dom.searchInput.focus();
});

/* ════════════════════════════════════════════════════════════ *
 *  INIT                                                        *
 * ════════════════════════════════════════════════════════════ */

(async function init() {
  await fetchMappings();

  const params = new URLSearchParams(window.location.search);
  if (params.get('create') === '1') {
    openModal(null);
    history.replaceState(null, '', window.location.pathname);
  }
})();
