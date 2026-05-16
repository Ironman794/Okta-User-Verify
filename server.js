require('dotenv').config();

const express = require('express');
const path = require('path');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

// Configuration
const OKTA_ORG_URL = (process.env.OKTA_ORG_URL || '').replace(/\/+$/, '');
const OKTA_API_TOKEN = process.env.OKTA_API_TOKEN;
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';
const FETCH_TIMEOUT = parseInt(process.env.FETCH_TIMEOUT || '10000', 10);
const POLL_TIMEOUT = parseInt(process.env.POLL_TIMEOUT || '60000', 10);
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL || '3000', 10);

// Validate required environment variables
if (!OKTA_ORG_URL || !OKTA_API_TOKEN) {
  console.error('ERROR: OKTA_ORG_URL or OKTA_API_TOKEN not set');
  process.exit(1);
}

// Validate OKTA_ORG_URL format
try {
  new URL(OKTA_ORG_URL);
} catch {
  console.error('ERROR: OKTA_ORG_URL is not a valid URL');
  process.exit(1);
}

// Rate Limiters
const verifyPushLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many push verification requests, please try again later'
});

const oktaLookupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many lookup requests, please try again later'
});

const rootPageLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
});

// Middleware for request correlation IDs
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuidv4();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Error handler middleware
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Parse JSON response text with fallback to raw text
 * @param {string} text - Response text to parse
 * @returns {object} Parsed JSON or object with raw text
 */
function parseJsonResponse(text) {
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    return { raw: text };
  }
}

/**
 * Fetch with timeout support
 * @param {string} url - URL to fetch
 * @param {object} options - Fetch options
 * @param {number} timeoutMs - Timeout in milliseconds
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Make authenticated request to Okta API
 * @param {string} pathFragment - API path (e.g., /api/v1/users)
 * @param {object} options - Fetch options
 * @returns {Promise<object>} Parsed response data
 * @throws {Error} If request fails or response is not ok
 */
async function oktaRequest(pathFragment, options = {}) {
  const url = `${OKTA_ORG_URL}${pathFragment}`;
  
  try {
    const resp = await fetchWithTimeout(url, {
      ...options,
      headers: {
        Authorization: `SSWS ${OKTA_API_TOKEN}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    });

    const text = await resp.text();
    const data = parseJsonResponse(text);

    if (!resp.ok) {
      const error = new Error(`OKTA_API_ERROR ${resp.status}`);
      error.status = resp.status;
      error.path = pathFragment;
      error.response = data;
      throw error;
    }

    return data;
  } catch (err) {
    if (err.name === 'AbortError') {
      const timeoutError = new Error(`OKTA_TIMEOUT: Request to ${pathFragment} timed out after ${FETCH_TIMEOUT}ms`);
      timeoutError.originalError = err;
      throw timeoutError;
    }
    throw err;
  }
}

/**
 * Find Okta user by login
 * @param {string} login - User login/username
 * @returns {Promise<object>} User object
 * @throws {Error} USER_NOT_FOUND or AMBIGUOUS_USER_MATCH
 */
async function findUserByLogin(login) {
  if (!login || typeof login !== 'string' || login.length === 0) {
    throw new Error('INVALID_LOGIN: Login must be a non-empty string');
  }

  const search = `profile.login eq "${login.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  const users = await oktaRequest(`/api/v1/users?search=${encodeURIComponent(search)}`);

  if (!Array.isArray(users) || users.length === 0) {
    const error = new Error('USER_NOT_FOUND');
    error.code = 'USER_NOT_FOUND';
    throw error;
  }

  if (users.length > 1) {
    const exact = users.find(
      u => (u.profile?.login || '').toLowerCase() === login.toLowerCase()
    );
    if (!exact) {
      const error = new Error('AMBIGUOUS_USER_MATCH');
      error.code = 'AMBIGUOUS_USER_MATCH';
      throw error;
    }
    return exact;
  }

  return users[0];
}

/**
 * Get active Okta Verify push factor for user
 * @param {string} userId - Okta user ID
 * @returns {Promise<object>} Factor object
 * @throws {Error} NO_ACTIVE_PUSH_FACTOR
 */
async function getActivePushFactor(userId) {
  const factors = await oktaRequest(`/api/v1/users/${encodeURIComponent(userId)}/factors`);

  if (!Array.isArray(factors)) {
    throw new Error('INVALID_FACTORS_RESPONSE: Expected array of factors');
  }

  const pushFactors = factors.filter(
    f =>
      f.factorType === 'push' &&
      f.provider === 'OKTA' &&
      f.status === 'ACTIVE'
  );

  if (pushFactors.length === 0) {
    const error = new Error('NO_ACTIVE_PUSH_FACTOR');
    error.code = 'NO_ACTIVE_PUSH_FACTOR';
    throw error;
  }

  return pushFactors[0];
}

/**
 * Start push verification for user
 * @param {string} userId - Okta user ID
 * @param {string} factorId - Factor ID
 * @returns {Promise<object>} Object containing initial response and poll link
 * @throws {Error} If verification cannot be started
 */
async function startPushVerification(userId, factorId) {
  const verifyPath = `/api/v1/users/${encodeURIComponent(userId)}/factors/${encodeURIComponent(factorId)}/verify`;
  const data = await oktaRequest(verifyPath, {
    method: 'POST',
    body: JSON.stringify({})
  });

  const pollLink = data?._links?.poll?.href;
  if (!pollLink) {
    const error = new Error('NO_POLL_LINK: Okta did not return a poll link for verification');
    error.response = data;
    throw error;
  }

  return { initial: data, pollLink };
}

/**
 * Poll Okta for push verification result
 * @param {string} pollLink - Poll URL from Okta
 * @param {number} timeoutMs - Maximum time to poll in milliseconds
 * @param {number} pollIntervalMs - Interval between polls in milliseconds
 * @returns {Promise<object>} Result object with status
 */
async function pollPushResult(pollLink, timeoutMs = POLL_TIMEOUT, pollIntervalMs = POLL_INTERVAL) {
  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    try {
      const resp = await fetchWithTimeout(pollLink, {
        headers: {
          Authorization: `SSWS ${OKTA_API_TOKEN}`,
          Accept: 'application/json'
        }
      });

      const text = await resp.text();
      const data = parseJsonResponse(text);

      if (!resp.ok) {
        throw new Error(`POLL_FAILED ${resp.status}`);
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
    } catch (err) {
      if (err.name === 'AbortError') {
        // Timeout during poll, continue to next iteration
        await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
        continue;
      }
      throw err;
    }
  }

  return { status: 'timeout' };
}

// ============================================================================
// Routes
// ============================================================================

app.get('/', rootPageLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'public.html'));
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', requestId: req.id });
});

/**
 * GET /okta-user - Lookup Okta user by login
 */
app.get('/okta-user', oktaLookupLimiter, asyncHandler(async (req, res) => {
  const login = String(req.query.login || '').trim();
  
  if (!login) {
    return res.status(400).json({ 
      error: 'login query param is required',
      requestId: req.id 
    });
  }

  try {
    const user = await findUserByLogin(login);
    res.json({ user, requestId: req.id });
  } catch (err) {
    const code = err.code || 'UNKNOWN_ERROR';
    
    if (code === 'USER_NOT_FOUND') {
      return res.status(404).json({ 
        error: 'User not found',
        requestId: req.id 
      });
    }
    
    if (code === 'AMBIGUOUS_USER_MATCH') {
      return res.status(409).json({ 
        error: 'Ambiguous user match',
        requestId: req.id 
      });
    }
    
    console.error(`[${req.id}] User lookup error:`, err);
    res.status(500).json({ 
      error: 'Error looking up user', 
      details: err.message,
      requestId: req.id 
    });
  }
}));

/**
 * GET /okta-factors - List user's Okta factors by login
 */
app.get('/okta-factors', oktaLookupLimiter, asyncHandler(async (req, res) => {
  const login = String(req.query.login || '').trim();
  
  if (!login) {
    return res.status(400).json({ 
      error: 'login query param is required',
      requestId: req.id 
    });
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
      })),
      requestId: req.id
    });
  } catch (err) {
    console.error(`[${req.id}] Factors lookup error:`, err);
    res.status(500).json({ 
      error: 'Error retrieving factors', 
      details: err.message,
      requestId: req.id 
    });
  }
}));

/**
 * POST /verify/push - Verify user via Okta push notification
 */
app.post('/verify/push', verifyPushLimiter, asyncHandler(async (req, res) => {
  const login = String(req.body.login || '').trim();
  const agent = req.headers['x-agent-id'] || 'unknown';
  const caseId = req.body.caseId || 'none';
  const reason = req.body.reason || 'unspecified';

  if (!login) {
    return res.status(400).json({ 
      status: 'failed', 
      error: 'login is required',
      requestId: req.id 
    });
  }

  try {
    const user = await findUserByLogin(login);
    const pushFactor = await getActivePushFactor(user.id);
    const { initial, pollLink } = await startPushVerification(user.id, pushFactor.id);
    const result = await pollPushResult(pollLink);

    const logEntry = {
      event: 'PUSH_VERIFY',
      requestId: req.id,
      agent,
      caseId,
      reason,
      login,
      userId: user.id,
      factorId: pushFactor.id,
      result: result.status,
      initialFactorResult: initial.factorResult || null,
      timestamp: new Date().toISOString()
    };
    
    console.log(JSON.stringify(logEntry));

    if (result.status === 'verified') {
      return res.json({ status: 'verified', requestId: req.id });
    }

    if (result.status === 'failed') {
      return res.json({ 
        status: 'failed', 
        details: result.raw || null,
        requestId: req.id 
      });
    }

    if (result.status === 'timeout') {
      return res.json({ 
        status: 'timeout',
        requestId: req.id 
      });
    }

    return res.status(502).json({
      status: 'failed',
      error: 'Unexpected push verification state',
      details: result.raw || null,
      requestId: req.id
    });
  } catch (err) {
    const code = err.code || 'UNKNOWN_ERROR';
    console.error('[%s] Push verification error:', req.id, err);

    if (code === 'USER_NOT_FOUND') {
      return res.status(404).json({ 
        status: 'failed', 
        error: 'User not found',
        requestId: req.id 
      });
    }

    if (code === 'AMBIGUOUS_USER_MATCH') {
      return res.status(409).json({ 
        status: 'failed', 
        error: 'Ambiguous user match',
        requestId: req.id 
      });
    }

    if (code === 'NO_ACTIVE_PUSH_FACTOR') {
      return res.status(400).json({
        status: 'failed',
        error: 'User has no active Okta Verify push factor',
        requestId: req.id
      });
    }

    return res.status(500).json({
      status: 'failed',
      error: 'Error during push verification',
      details: err.message,
      requestId: req.id
    });
  }
}));

// Global error handler middleware
app.use((err, req, res, next) => {
  console.error(`[${req?.id}] Unhandled error:`, err);
  
  res.status(err.status || 500).json({
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined,
    requestId: req?.id
  });
});

// ============================================================================
// Server startup
// ============================================================================

const server = app.listen(PORT, HOST, () => {
  console.log(`Okta User Verify backend listening on http://${HOST}:${PORT}`);
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(`${signal} received, shutting down gracefully...`);
  
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
  
  // Force shutdown after 10 seconds
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});
