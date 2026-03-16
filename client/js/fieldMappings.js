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
let _options       = {};    // { label: [alias, ...] } for select-type mapping options
let _editingOptionOriginal = null;
let _editingKey    = null;  // null = create; string = edit key
let _pendingDelKey = null;  // key awaiting confirmed delete
let _isFetching    = false;
let _isSaving      = false;
let _isDeleting    = false;
let _searchQuery   = '';
const _rankUpdateInFlight = new Set();

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
  inputOrder:     $('inputOrder'),
  inputFieldType: $('inputFieldType'),
  optionsSection: $('optionsSection'),
  optionsList:    $('optionsList'),
  optionsError:   $('optionsError'),
  addOptionBtn:   $('addOptionBtn'),
  newOptionLabel: $('newOptionLabel'),
  newOptionAliases: $('newOptionAliases'),
  saveBtn:        $('saveBtn'),
  saveBtnLabel:   $('saveBtnLabel'),
  keyCount:       $('keyCount'),
  keyError:       $('keyError'),
  pathError:      $('pathError'),
  orderError:     $('orderError'),
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
      order:     Number.isFinite(m.order) ? m.order : 1,
      orderGroup: m.orderGroup || '',
      fieldType: m.fieldType || 'text',
      primary:   Array.isArray(m.primary)   ? m.primary   : [],
      secondary: Array.isArray(m.secondary) ? m.secondary : [],
      generic:   Array.isArray(m.generic)   ? m.generic   : [],
      negative:  Array.isArray(m.negative)  ? m.negative  : [],
      options:   (m.options && typeof m.options === 'object') ? m.options : {},
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
        <td class="adm-cell-rank">
          <span class="adm-rank-pill">#${escHtml(String(m.order || 1))}</span>
        </td>
        <td class="adm-cell-type"><span class="adm-type-badge adm-type-${escAttr(m.fieldType || 'text')}">${escHtml(m.fieldType || 'text')}</span></td>
        <td class="adm-cell-kw">${kwCell}</td>
        <td class="adm-cell-time">${m.updatedAt ? formatTime(m.updatedAt) : '—'}</td>
        <td class="adm-cell-actions">
          <button class="adm-tbl-btn adm-tbl-btn-ghost" data-action="move-up" data-key="${escAttr(m.key)}" aria-label="Move ${escAttr(m.key)} up">↑</button>
          <button class="adm-tbl-btn adm-tbl-btn-ghost" data-action="move-down" data-key="${escAttr(m.key)}" aria-label="Move ${escAttr(m.key)} down">↓</button>
          <input class="adm-rank-input" type="number" min="1" value="${escAttr(String(m.order || 1))}" data-rank-input="${escAttr(m.key)}" aria-label="Set rank for ${escAttr(m.key)}">
          <button class="adm-tbl-btn adm-tbl-btn-ghost" data-action="set-rank" data-key="${escAttr(m.key)}" aria-label="Set rank for ${escAttr(m.key)}">Set</button>
          <button class="adm-tbl-btn adm-tbl-btn-edit" data-action="edit" data-key="${escAttr(m.key)}" aria-label="Edit ${escAttr(m.key)}">Edit</button>
          <button class="adm-tbl-btn adm-tbl-btn-del"  data-action="delete" data-key="${escAttr(m.key)}" aria-label="Delete ${escAttr(m.key)}">Delete</button>
        </td>
      </tr>`;
  };

  const html = [];
  GROUP_DEFS.forEach(g => {
    const bucket = groupBuckets.get(g.key);
    if (!bucket || bucket.items.length === 0) return;
    html.push(`<tr class="fm-group-row"><td colspan="7">${escHtml(bucket.label)}</td></tr>`);
    bucket.items.forEach(m => html.push(renderRow(m)));
  });

  const otherBucket = groupBuckets.get('other');
  if (otherBucket && otherBucket.items.length > 0) {
    html.push(`<tr class="fm-group-row"><td colspan="7">${escHtml(otherBucket.label)}</td></tr>`);
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
  dom.inputOrder.value     = isEdit ? String(mapping.order || 1) : '';
  dom.inputFieldType.value = isEdit ? (mapping.fieldType || 'text') : 'text';
  dom.keyCount.textContent = `${dom.inputKey.value.length} / 40`;

  // Populate dropdown options state after fieldType is assigned
  _options = isEdit && mapping.options ? { ...mapping.options } : {};
  _editingOptionOriginal = null;
  resetOptionInputState();
  renderOptionsList();
  toggleOptionsSection(dom.inputFieldType.value);

  CATEGORIES.forEach(renderTags);
  clearAllErrors();

  dom.mappingModal.classList.add('show');
  setTimeout(() => (isEdit ? dom.inputPath : dom.inputKey).focus(), 60);
}

function closeModal() {
  dom.mappingModal.classList.remove('show');
  _editingKey = null;
  _options    = {};
  _editingOptionOriginal = null;
  CATEGORIES.forEach(cat => {
    _kw[cat] = [];
    kwDom[cat].input.value = '';
    renderTags(cat);
  });
  dom.mappingForm.reset();
  dom.inputOrder.value = '';
  clearAllErrors();
  toggleOptionsSection('text');
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
  const orderRaw = dom.inputOrder.value.trim();

  if (!_editingKey) {
    if (!key)                                    errors.key = 'Key is required.';
    else if (key.length > 40)                    errors.key = 'Key must be 40 characters or fewer.';
    else if (!KEY_RE.test(key))                  errors.key = 'Key must contain only letters, numbers, dots, underscores, or hyphens.';
    else if (_mappings.some(m => m.key === key)) errors.key = `A mapping for "${key}" already exists.`;
  }

  if (!path)                   errors.path = 'Path is required.';
  else if (path.length > 100)  errors.path = 'Path must be 100 characters or fewer.';
  else if (!PATH_RE.test(path)) errors.path = 'Path must contain only letters, numbers, dots, underscores, or hyphens.';

  if (orderRaw) {
    const rank = Number.parseInt(orderRaw, 10);
    if (!Number.isFinite(rank) || rank < 1) {
      errors.order = 'Rank must be a positive integer.';
    }
  }

  // Only primary is required
  if (_kw.primary.length === 0)              errors.primary = 'At least one primary keyword is required.';
  else if (_kw.primary.length > KW_MAX.primary) errors.primary = `Maximum ${KW_MAX.primary} primary keywords allowed.`;

  CATEGORIES.slice(1).forEach(cat => {
    if (_kw[cat].length > KW_MAX[cat]) errors[cat] = `Maximum ${KW_MAX[cat]} ${cat} keywords allowed.`;
  });

  if (dom.inputFieldType.value === 'select' && Object.keys(_options).length === 0) {
    errors.options = 'At least one dropdown option is required for select fields.';
  }

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
    if (errors.order)   { showFieldError('orderError',   errors.order);   dom.inputOrder.focus(); return; }
    if (errors.primary) { showFieldError('primaryError', errors.primary);                        return; }
    if (errors.options) { showFieldError('optionsError', errors.options);                        return; }
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
    // Include options only when fieldType is select (prevents unnecessary DB fields)
    ...(dom.inputFieldType.value === 'select' ? { options: _options } : {}),
  };

  const rankRaw = dom.inputOrder.value.trim();
  if (rankRaw) {
    payload.order = Number.parseInt(rankRaw, 10);
  }

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

function setRankUpdatingState(key, on, triggerAction = null) {
  const row = dom.fmBody.querySelector(`tr[data-key="${escAttr(key)}"]`);
  if (!row) return;

  row.classList.toggle('is-rank-updating', on);

  row.querySelectorAll('[data-action], [data-rank-input]').forEach((el) => {
    el.disabled = on;
  });

  const actionButtons = row.querySelectorAll('[data-action]');
  actionButtons.forEach((btn) => {
    if (!btn.dataset.defaultLabel) {
      btn.dataset.defaultLabel = btn.textContent;
    }
    if (on && btn.dataset.action === triggerAction) {
      btn.textContent = 'Updating…';
    } else {
      btn.textContent = btn.dataset.defaultLabel;
    }
  });
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

async function reorderMapping(key, payload, triggerAction = null) {
  if (_rankUpdateInFlight.has(key)) return;

  _rankUpdateInFlight.add(key);
  setRankUpdatingState(key, true, triggerAction);
  showToast('Rank is updating. Please wait…', '', 2000);

  try {
    await apiFetch(`/admin/field-mappings/${encodeURIComponent(key)}/reorder`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
    await fetchMappings({ highlightKey: key });
    notifyMappingsChanged();
    showToast('Rank updated.', 'success');
  } catch (err) {
    if (err.message !== 'UNAUTHORIZED' && err.message !== 'FORBIDDEN') {
      showToast(err.message || 'Failed to reorder mapping.', 'error');
    }
  } finally {
    _rankUpdateInFlight.delete(key);
    setRankUpdatingState(key, false);
  }
}

async function moveMapping(key, direction) {
  if (!key) return;
  await reorderMapping(key, { direction }, direction === 'up' ? 'move-up' : 'move-down');
}

async function setMappingRank(key, rank) {
  if (!Number.isFinite(rank) || rank < 1) {
    showToast('Rank must be a positive integer.', 'error');
    return;
  }
  await reorderMapping(key, { order: rank }, 'set-rank');
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
  const inputMap = { keyError: dom.inputKey, pathError: dom.inputPath, orderError: dom.inputOrder };
  if (inputMap[id]) inputMap[id].classList.add('is-error');
}

function clearFieldError(id) {
  const el = $(id);
  if (!el) return;
  el.textContent = '';
  el.hidden = true;
  const catMatch = id.match(/^(primary|secondary|generic|negative)Error$/);
  if (catMatch) { kwDom[catMatch[1]].input.classList.remove('is-error'); return; }
  const inputMap = { keyError: dom.inputKey, pathError: dom.inputPath, orderError: dom.inputOrder };
  if (inputMap[id]) inputMap[id].classList.remove('is-error');
}

function clearAllErrors() {
  ['keyError', 'pathError', 'orderError', 'primaryError', 'secondaryError', 'genericError', 'negativeError', 'optionsError']
    .forEach(id => clearFieldError(id));
}

/* ════════════════════════════════════════════════════════════ *
 *  DROPDOWN OPTIONS MANAGEMENT (Fix #5)                        *
 * ════════════════════════════════════════════════════════════ */

/** Show or hide the options section based on selected fieldType. */
function toggleOptionsSection(fieldType) {
  if (dom.optionsSection) dom.optionsSection.style.display = (fieldType === 'select') ? '' : 'none';
  if (fieldType !== 'select') {
    clearFieldError('optionsError');
    _editingOptionOriginal = null;
    resetOptionInputState();
  }
}

/** Re-render the options list rows from _options state. */
function renderOptionsList() {
  const listEl = dom.optionsList;
  if (!listEl) return;
  const entries = Object.entries(_options);
  if (entries.length === 0) {
    listEl.innerHTML = '<p style="font-size:0.8rem;color:var(--muted);margin:0;">No options yet. Add the first one below.</p>';
    return;
  }
  listEl.innerHTML = entries.map(([label, aliases], i) => `
    <div style="display:flex;align-items:center;gap:8px;background:var(--surface-2,#f8fafc);border:1px solid var(--border);border-radius:6px;padding:8px 10px;">
      <strong style="flex:0 0 auto;min-width:80px;font-size:0.84rem;">${escHtml(label)}</strong>
      <span style="flex:1;font-size:0.78rem;color:var(--muted);">${aliases.map(escHtml).join(', ') || '—'}</span>
      <button type="button" class="adm-tbl-btn adm-tbl-btn-edit" data-opt-edit="${i}"
        aria-label="Edit option ${escAttr(label)}">Edit</button>
      <button type="button" class="adm-tbl-btn adm-tbl-btn-del" data-opt-remove="${i}"
        aria-label="Remove option ${escAttr(label)}">Remove</button>
    </div>
  `).join('');

  // Wire remove buttons
  listEl.querySelectorAll('[data-opt-remove]').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.optRemove, 10);
      const labels = Object.keys(_options);
      if (!isNaN(idx) && labels[idx]) {
        delete _options[labels[idx]];
        if (_editingOptionOriginal === labels[idx]) {
          _editingOptionOriginal = null;
          resetOptionInputState();
        }
        renderOptionsList();
      }
    });
  });

  // Wire edit buttons
  listEl.querySelectorAll('[data-opt-edit]').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.optEdit, 10);
      const labels = Object.keys(_options);
      const original = !isNaN(idx) ? labels[idx] : null;
      if (!original) return;
      _editingOptionOriginal = original;
      dom.newOptionLabel.value = original;
      dom.newOptionAliases.value = (_options[original] || []).join(', ');
      dom.addOptionBtn.textContent = 'Update Option';
      clearFieldError('optionsError');
      dom.newOptionLabel.focus();
    });
  });
}

/** Add a new option from the label/aliases inputs. */
function addOptionFromInputs() {
  const labelEl   = dom.newOptionLabel;
  const aliasesEl = dom.newOptionAliases;
  const errEl     = dom.optionsError;
  if (!labelEl || !aliasesEl) return;

  const label = labelEl.value.trim();
  if (!label) {
    if (errEl) { errEl.textContent = 'Option label is required.'; errEl.hidden = false; }
    labelEl.focus();
    return;
  }
  if (label.length > 100 || /[${}\\]/.test(label)) {
    if (errEl) { errEl.textContent = 'Invalid option label.'; errEl.hidden = false; }
    return;
  }

  const aliases = aliasesEl.value
    .split(',')
    .map(a => a.trim().toLowerCase())
    .filter(a => a.length > 0 && a.length <= 100 && !/[${}\\]/.test(a));

  // Rename support: if label changed while editing, remove old key first.
  if (_editingOptionOriginal && _editingOptionOriginal !== label) {
    delete _options[_editingOptionOriginal];
  }
  _options[label] = aliases;
  _editingOptionOriginal = null;
  if (errEl) { errEl.textContent = ''; errEl.hidden = true; }
  labelEl.value = '';
  aliasesEl.value = '';
  resetOptionInputState();
  renderOptionsList();
}

function resetOptionInputState() {
  if (dom.addOptionBtn) dom.addOptionBtn.textContent = '+ Add Option';
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
  } else if (action === 'move-up') {
    moveMapping(key, 'up');
  } else if (action === 'move-down') {
    moveMapping(key, 'down');
  } else if (action === 'set-rank') {
    const input = Array.from(dom.fmBody.querySelectorAll('[data-rank-input]'))
      .find((el) => el.dataset.rankInput === key);
    const rank = Number.parseInt(input?.value || '', 10);
    setMappingRank(key, rank);
  } else if (action === 'delete') {
    deleteMapping(key);
  }
});

// Table: double-click any row/cell to open edit modal
dom.fmBody.addEventListener('dblclick', (e) => {
  // Ignore explicit action controls; they already have handlers
  if (e.target.closest('button') || e.target.closest('input')) return;

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
dom.inputOrder.addEventListener('input', () => clearFieldError('orderError'));

dom.fmBody.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const input = e.target.closest('[data-rank-input]');
  if (!input) return;
  e.preventDefault();
  const key = input.dataset.rankInput;
  const rank = Number.parseInt(input.value || '', 10);
  setMappingRank(key, rank);
});

// Show/hide options section when field type changes
dom.inputFieldType.addEventListener('change', () => {
  toggleOptionsSection(dom.inputFieldType.value);
});

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

// Add Option button and Enter key in option inputs (Fix #5)
if (dom.addOptionBtn) dom.addOptionBtn.addEventListener('click', addOptionFromInputs);
if (dom.newOptionLabel) {
  dom.newOptionLabel.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); addOptionFromInputs(); }
  });
}
if (dom.newOptionAliases) {
  dom.newOptionAliases.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); addOptionFromInputs(); }
  });
}

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
