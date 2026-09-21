import http from 'node:http';

const PORT = Number(process.env.PORT || 8080);
const SHARED_SECRET = process.env.GATEWAY_SHARED_SECRET || '';
const CLIENT_ID = process.env.FATSECRET_CLIENT_ID || '';
const CLIENT_SECRET = process.env.FATSECRET_CLIENT_SECRET || '';
const DEFAULT_SCOPE = process.env.FATSECRET_SCOPE || 'premier localization';

const ALLOWED_PATHS = new Set([
  'recipes/search/v3',
  'recipes/search/v2',
  'recipe/v2',
]);

const ALLOWED_METHODS = new Set([
  'recipes.search.v3',
  'recipes.search.v2',
  'recipe.get.v2',
]);

let tokenCache = null;

function send(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(JSON.stringify(body));
}

async function readJson(req) {
  const chunks = [];

  for await (const chunk of req) {
    chunks.push(chunk);
  }

  const size = chunks.reduce((n, c) => n + c.length, 0);

  if (size > 64 * 1024) {
    throw new Error('request too large');
  }

  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

async function token(scope = DEFAULT_SCOPE) {
  if (tokenCache && tokenCache.expiresAt > Date.now() + 30_000) {
    return tokenCache.value;
  }

  if (!CLIENT_ID || !CLIENT_SECRET) {
    throw new Error('FatSecret credentials missing');
  }

  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    scope,
  });

  const response = await fetch(
    'https://oauth.fatsecret.com/connect/token',
    {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(
          `${CLIENT_ID}:${CLIENT_SECRET}`
        ).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body,
    }
  );

  const payload = await response.json().catch(() => null);

  if (!response.ok || !payload?.access_token) {
    const error = new Error(
      `FatSecret OAuth failed (${response.status})`
    );
    error.status = 502;
    error.payload = payload;
    throw error;
  }

  tokenCache = {
    value: String(payload.access_token),
    expiresAt:
      Date.now() +
      Math.max(60, Number(payload.expires_in) || 3600) * 1000,
  };

  return tokenCache.value;
}

async function fatsecret(body) {
  const accessToken = await token(
    String(body.scope || DEFAULT_SCOPE)
  );

  const params = new URLSearchParams();

  for (const [key, value] of Object.entries(body.params || {})) {
    if (value !== undefined && value !== null) {
      params.set(key, String(value));
    }
  }

  params.set('format', 'json');

  let response;

  if (body.transport === 'path') {
    if (!ALLOWED_PATHS.has(body.path)) {
      throw Object.assign(new Error('path not allowed'), {
        status: 400,
      });
    }

    response = await fetch(
      `https://platform.fatsecret.com/rest/${body.path}?${params.toString()}`,
      {
        headers: {
          authorization: `Bearer ${accessToken}`,
          accept: 'application/json',
        },
      }
    );
  } else if (body.transport === 'method') {
    if (!ALLOWED_METHODS.has(body.method)) {
      throw Object.assign(new Error('method not allowed'), {
        status: 400,
      });
    }

    params.set('method', body.method);

    response = await fetch(
      'https://platform.fatsecret.com/rest/server.api',
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${accessToken}`,
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'application/json',
        },
        body: params,
      }
    );
  } else {
    throw Object.assign(new Error('transport not allowed'), {
      status: 400,
    });
  }

  const payload = await response.json().catch(() => null);

  return {
    status: response.status,
    payload,
  };
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return send(res, 200, { ok: true });
    }

    if (req.method !== 'POST' || req.url !== '/fatsecret') {
      return send(res, 404, { error: 'not found' });
    }

    if (
      !SHARED_SECRET ||
      req.headers['x-peakmode-gateway-secret'] !== SHARED_SECRET
    ) {
      return send(res, 401, { error: 'unauthorized' });
    }

    const body = await readJson(req);
    const result = await fatsecret(body);

    return send(res, 200, result);
  } catch (error) {
    return send(res, error?.status || 500, {
      error: error?.message || 'gateway error',
      payload: error?.payload || null,
    });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`PeakMode FatSecret gateway listening on ${PORT}`);
});
