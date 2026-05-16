require('dotenv').config();

const express = require('express');
const path = require('path');
const rateLimit = require('express-rate-limit');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(express.json());

const verifyPushLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
});

const oktaLookupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const rootPageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});

const OKTA_ORG_URL = (process.env.OKTA_ORG_URL || '').replace(/\/+$/, '');
const OKTA_API_TOKEN = process.env.OKTA_API_TOKEN;
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

if (!OKTA_ORG_URL || !OKTA_API_TOKEN) {
  console.error('ERROR: OKTA_ORG_URL or OKTA_API_TOKEN not set');
  process.exit(1);
}

app.get('/', rootPageLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'public.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

async function oktaRequest(pathFragment, options = {}) {
  const url = `${OKTA_ORG_URL}${pathFragment}`;
  const resp = await fetch(url, {
    ...options,
    headers: {
      Authorization: `SSWS ${OKTA_API_TOKEN}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...(options.headers || {})
    }
  });

  const text = await resp.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!resp.ok) {
    throw new Error(
      `OKTA_API_ERROR ${resp.status} ${pathFragment} ${JSON.stringify(data)}`
    );
  }

  return data;
}

async function findUserByLogin(login) {
  const search = `profile.login eq "${login}"`;
  const users = await oktaRequest(`/api/v1/users?search=${encodeURIComponent(search)}`);

  if (!Array.isArray(users) || users.length === 0) {
    throw new Error('USER_NOT_FOUND');
  }

  if (users.length > 1) {
    const exact = users.find(
      u => (u.profile?.login || '').toLowerCase() === login.toLowerCase()
    );
    if (!exact) throw new Error('AMBIGUOUS_USER_MATCH');
    return exact;
  }

  return users[0];
}

async function getActivePushFactor(userId) {
  const factors = await oktaRequest(`/api/v1/users/${encodeURIComponent(userId)}/factors`);

  const pushFactors = factors.filter(
    f =>
      f.factorType === 'push' &&
      f.provider === 'OKTA' &&
      f.status === 'ACTIVE'
  );

  if (pushFactors.length === 0) {
    throw new Error('NO_ACTIVE_PUSH_FACTOR');
  }

  return pushFactors[0];
}

async function startPushVerification(userId, factorId) {
  const verifyPath = `/api/v1/users/${encodeURIComponent(userId)}/factors/${encodeURIComponent(factorId)}/verify`;
  const data = await oktaRequest(verifyPath, {
    method: 'POST',
    body: JSON.stringify({})
  });

  const pollLink = data?._links?.poll?.href;
  if (!pollLink) {
    throw new Error(`NO_POLL_LINK ${JSON.stringify(data)}`);
  }

  return { initial: data, pollLink };
}

async function pollPushResult(pollLink, timeoutMs = 60000, pollIntervalMs = 3000) {
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    const resp = await fetch(pollLink, {
      headers: {
        Authorization: `SSWS ${OKTA_API_TOKEN}`,
        Accept: 'application/json'
      }
    });

    const text = await resp.text();
    let data = {};
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }

    if (!resp.ok) {
      throw new Error(`POLL_FAILED ${resp.status} ${JSON.stringify(data)}`);
    }

    const factorResult = String(data.factorResult || '').toUpperCase();
    const status = String(data.status || '').toUpperCase();

    if (factorResult === 'SUCCESS' || factorResult === 'PASS') {
      return { status: 'verified', raw: data };
    }

    if (
      factorResult === 'REJECTED' ||
      factorResult === 'FAILED' ||
      factorResult === 'DENIED' ||
      status === 'TIMEOUT'
    ) {
      return { status: 'failed', raw: data };
    }

    if (factorResult === 'WAITING' || status === 'MFA_CHALLENGE' || !factorResult) {
      await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
      continue;
    }

    return { status: 'unknown', raw: data };
  }

  return { status: 'timeout' };
}

app.get('/okta-user', oktaLookupLimiter, async (req, res) => {
  const login = String(req.query.login || '').trim();
  if (!login) {
    return res.status(400).json({ error: 'login query param is required' });
  }

  try {
    const user = await findUserByLogin(login);
    res.json(user);
  } catch (err) {
    const msg = err.message || 'Unknown error';
    if (msg === 'USER_NOT_FOUND') {
      return res.status(404).json({ error: 'User not found' });
    }
    if (msg === 'AMBIGUOUS_USER_MATCH') {
      return res.status(409).json({ error: 'Ambiguous user match' });
    }
    console.error(err);
    res.status(500).json({ error: 'Error looking up user', details: msg });
  }
});

app.get('/okta-factors', oktaLookupLimiter, async (req, res) => {
  const login = String(req.query.login || '').trim();
  if (!login) {
    return res.status(400).json({ error: 'login query param is required' });
  }

  try {
    const user = await findUserByLogin(login);
    const factors = await oktaRequest(`/api/v1/users/${encodeURIComponent(user.id)}/factors`);
    res.json({
      userId: user.id,
      login: user.profile?.login,
      factors: factors.map(f => ({
        id: f.id,
        factorType: f.factorType,
        provider: f.provider,
        status: f.status
      }))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error retrieving factors', details: err.message });
  }
});

app.post('/verify/push', verifyPushLimiter, async (req, res) => {
  const login = String(req.body.login || '').trim();
  const agent = req.headers['x-agent-id'] || 'unknown';
  const caseId = req.body.caseId || 'none';
  const reason = req.body.reason || 'unspecified';

  if (!login) {
    return res.status(400).json({ status: 'failed', error: 'login is required' });
  }

  try {
    const user = await findUserByLogin(login);
    const pushFactor = await getActivePushFactor(user.id);
    const { initial, pollLink } = await startPushVerification(user.id, pushFactor.id);
    const result = await pollPushResult(pollLink);

    console.log(JSON.stringify({
      event: 'PUSH_VERIFY',
      agent,
      caseId,
      reason,
      login,
      userId: user.id,
      factorId: pushFactor.id,
      result: result.status,
      initialFactorResult: initial.factorResult || null,
      time: new Date().toISOString()
    }));

    if (result.status === 'verified') {
      return res.json({ status: 'verified' });
    }

    if (result.status === 'failed') {
      return res.json({ status: 'failed', details: result.raw || null });
    }

    if (result.status === 'timeout') {
      return res.json({ status: 'timeout' });
    }

    return res.status(502).json({
      status: 'failed',
      error: 'Unexpected push verification state',
      details: result.raw || null
    });
  } catch (err) {
    console.error(err);

    if (err.message === 'USER_NOT_FOUND') {
      return res.status(404).json({ status: 'failed', error: 'User not found' });
    }

    if (err.message === 'AMBIGUOUS_USER_MATCH') {
      return res.status(409).json({ status: 'failed', error: 'Ambiguous user match' });
    }

    if (err.message === 'NO_ACTIVE_PUSH_FACTOR') {
      return res.status(400).json({
        status: 'failed',
        error: 'User has no active Okta Verify push factor'
      });
    }

    return res.status(500).json({
      status: 'failed',
      error: 'Error during push verification',
      details: err.message
    });
  }
});

app.listen(PORT, HOST, () => {
  console.log(`Caller Verify backend listening on http://${HOST}:${PORT}`);
});