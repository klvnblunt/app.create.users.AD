const $ = (s, root = document) => root.querySelector(s);
const rowsEl = $('#rows');
let lastUnit = UNITS[0] || '';
let previa = [];

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else n.setAttribute(k, v);
  }
  kids.forEach(c => n.append(c));
  return n;
}

function showMsg(text) {
  const m = $('#msg');
  m.textContent = text;
  m.hidden = !text;
}

function showStep(name) {
  for (const s of ['form', 'preview', 'result']) $('#step-' + s).hidden = s !== name;
  window.scrollTo({ top: 0 });
}

function addRow(nome = '', unidade = lastUnit, after = null) {
  const row = el('div', { class: 'row' });
  const input = el('input', { type: 'text', class: 'nome', placeholder: 'Nome completo', autocomplete: 'off', 'aria-label': 'Nome completo' });
  const sel = el('select', { class: 'unidade', 'aria-label': 'Unidade' });
  UNITS.forEach(u => sel.add(new Option(u, u)));
  sel.value = unidade;
  input.value = nome;
  const rm = el('button', { type: 'button', class: 'icon', title: 'Remover', 'aria-label': 'Remover usuário', text: '×' });

  sel.addEventListener('change', () => { lastUnit = sel.value; });
  rm.addEventListener('click', () => {
    if (rowsEl.children.length > 1) row.remove(); else input.value = '';
  });
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addRow('', sel.value, row).querySelector('.nome').focus();
    }
  });
  input.addEventListener('paste', e => {
    const txt = (e.clipboardData || window.clipboardData).getData('text');
    const linhas = txt.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    if (linhas.length > 1) {
      e.preventDefault();
      input.value = linhas[0];
      let ref = row;
      linhas.slice(1).forEach(l => { ref = addRow(l, sel.value, ref); });
    }
  });

  row.append(el('div', { class: 'combo' }, input, sel), rm);
  if (after) after.after(row); else rowsEl.append(row);
  return row;
}

async function api(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await r.json(); } catch (_) { /* sem corpo */ }
  if (r.status === 401) { location.href = '/login'; return null; }
  if (!r.ok) throw new Error((data && data.erro) || 'Erro inesperado (' + r.status + ').');
  return data;
}

function coletar() {
  return [...rowsEl.children]
    .map(r => ({ nome: $('.nome', r).value.trim(), unidade: $('.unidade', r).value }))
    .filter(l => l.nome);
}

function contarValidos() {
  const n = previa.filter(l => !l.erro).length;
  const b = $('#create');
  b.textContent = n === 1 ? 'Criar 1 usuário' : `Criar ${n} usuários`;
  b.disabled = n === 0;
}

function renderPreview() {
  const body = $('#prev-body');
  body.replaceChildren();
  previa.forEach(l => {
    const input = el('input', { type: 'text', class: 'login mono', maxlength: '20', spellcheck: 'false', 'aria-label': 'Login de ' + l.nome });
    input.value = l.login || '';
    input.disabled = !!l.erro;
    const chip = l.erro ? el('span', { class: 'chip err', text: l.erro })
      : l.aviso ? el('span', { class: 'chip warn', text: l.aviso })
      : el('span', { class: 'chip ok', text: 'Pronto' });
    body.append(el('tr', {},
      el('td', { text: l.nome }),
      el('td', { text: l.unidade }),
      el('td', {}, el('div', { class: 'login-cell' }, input, el('span', { class: 'suffix mono', text: '@' + UPN }))),
      el('td', {}, chip)));
  });
  contarValidos();
}

function renderResultado(lista) {
  const body = $('#res-body');
  body.replaceChildren();
  lista.forEach(r => {
    body.append(el('tr', {},
      el('td', { text: r.nome }),
      el('td', { text: r.unidade || '' }),
      el('td', { class: 'mono', text: r.login }),
      el('td', {}, el('span', { class: 'chip ' + (r.ok ? 'ok' : 'err'), text: r.ok ? 'Criado' : 'Erro' }),
        el('div', { class: 'sub', text: r.msg }))));
  });
  const ok = lista.filter(r => r.ok).length;
  const falhas = lista.length - ok;
  $('#summary').textContent = `${ok} criado(s)` + (falhas ? `, ${falhas} com erro.` : '.');
}

$('#add').addEventListener('click', () => {
  const last = rowsEl.lastElementChild;
  addRow('', last ? $('.unidade', last).value : lastUnit).querySelector('.nome').focus();
});

$('#preview').addEventListener('click', async e => {
  const linhas = coletar();
  if (!linhas.length) { showMsg('Digite pelo menos um nome.'); return; }
  showMsg('');
  e.target.disabled = true;
  try {
    const d = await api('/api/preview', { linhas });
    if (!d) return;
    previa = d.linhas;
    renderPreview();
    showStep('preview');
  } catch (err) {
    showMsg(err.message);
  } finally {
    e.target.disabled = false;
  }
});

$('#back').addEventListener('click', () => showStep('form'));

$('#create').addEventListener('click', async e => {
  const inputs = [...document.querySelectorAll('#prev-body .login')];
  const linhas = [];
  previa.forEach((l, i) => {
    if (!l.erro) linhas.push({ nome: l.nome, unidade: l.unidade, login: inputs[i].value.trim().toLowerCase() });
  });
  e.target.disabled = true;
  try {
    const d = await api('/api/criar', { linhas });
    if (!d) return;
    renderResultado(d.resultados);
    showStep('result');
  } catch (err) {
    showMsg(err.message);
    showStep('form');
  } finally {
    e.target.disabled = false;
  }
});

$('#again').addEventListener('click', () => {
  rowsEl.replaceChildren();
  addRow();
  showMsg('');
  showStep('form');
  $('.nome', rowsEl).focus();
});

if (UNITS.length) addRow(); else $('#preview').disabled = true;
