const AUTH_API_BASE = "https://sandooq-games-api.sandooq-m.workers.dev";
const GAME_ID = "education";
const PRODUCT_PAGE_URL = "https://sandooq-games.com/edu-games.html?access=required#purchase";

const ACCESS_TOKEN_COOKIE = "education_site_token_v1";
const ACCESS_GAME_COOKIE = "education_site_game_v1";
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;

const TOKEN_QUERY_KEYS = [
  "sg_token",
  "sandooq_token",
  "access_token",
  "token"
];

const GAME_QUERY_KEYS = [
  "sg_game",
  "game_id",
  "game"
];

const TEMP_QUERY_KEYS = [
  "sg_temp",
  "temporary",
  "is_temporary",
  "sg_device"
];

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);

  if (!shouldProtect(request, url.pathname)) {
    return next();
  }

  const access = await verifyEducationAccess(request, url);

  if (!access.allowed) {
    return redirectToProductPage();
  }

  if (access.redirectCleanUrl) {
    return redirectToCleanUrl(url, access.cookiesToSet);
  }

  const response = await next();
  return addProtectionHeaders(response, access.cookiesToSet);
}

function shouldProtect(request, pathname) {
  const method = String(request.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;

  const lower = String(pathname || "/").toLowerCase();

  if (lower.startsWith("/api/")) return false;

  const publicExtensions = [
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico",
    ".css", ".js", ".mjs", ".map", ".json", ".txt", ".xml",
    ".ttf", ".otf", ".woff", ".woff2",
    ".mp3", ".wav", ".ogg", ".mp4", ".webm"
  ];

  if (publicExtensions.some(extension => lower.endsWith(extension))) {
    return false;
  }

  return lower === "/" || lower.endsWith(".html");
}

async function verifyEducationAccess(request, currentUrl) {
  const cookies = parseCookies(request.headers.get("cookie") || "");

  const tokenFromQuery = readFirstQueryValue(currentUrl, TOKEN_QUERY_KEYS);
  const tokenFromCookie = String(cookies[ACCESS_TOKEN_COOKIE] || "").trim();
  const token = tokenFromQuery || tokenFromCookie;

  if (!token) {
    return { allowed: false, cookiesToSet: [], redirectCleanUrl: false };
  }

  const gameFromQuery = normalizeGameId(readFirstQueryValue(currentUrl, GAME_QUERY_KEYS));
  const rawGameFromQuery = readFirstQueryValue(currentUrl, GAME_QUERY_KEYS);
  const gameFromCookie = normalizeGameId(cookies[ACCESS_GAME_COOKIE]);

  if (rawGameFromQuery && !gameFromQuery) {
    return { allowed: false, cookiesToSet: [], redirectCleanUrl: false };
  }

  if (cookies[ACCESS_GAME_COOKIE] && !gameFromCookie) {
    return { allowed: false, cookiesToSet: [], redirectCleanUrl: false };
  }

  const allowedByAccessEndpoint = await verifyViaGameAccessEndpoint(token);
  const allowed = allowedByAccessEndpoint || await verifyViaAccountEndpoint(token);

  if (!allowed) {
    return { allowed: false, cookiesToSet: [], redirectCleanUrl: false };
  }

  const cookiesToSet = [];

  if (tokenFromQuery || tokenFromCookie !== token) {
    cookiesToSet.push(buildSecureCookie(ACCESS_TOKEN_COOKIE, token, currentUrl));
  }

  if (gameFromCookie !== GAME_ID) {
    cookiesToSet.push(buildSecureCookie(ACCESS_GAME_COOKIE, GAME_ID, currentUrl));
  }

  return {
    allowed: true,
    cookiesToSet,
    redirectCleanUrl: hasAccessQuery(currentUrl)
  };
}

async function verifyViaGameAccessEndpoint(token) {
  try {
    const response = await fetch(`${AUTH_API_BASE}/api/game/access`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify({
        game_id: GAME_ID,
        device_token: createTemporaryDeviceToken(),
        device_name: "Education Site Access",
        is_temporary: true
      }),
      cache: "no-store"
    });

    let data = {};
    try {
      data = await response.json();
    } catch (_) {}

    return response.ok && isAllowedAccessResponse(data);
  } catch (_) {
    return false;
  }
}

async function verifyViaAccountEndpoint(token) {
  try {
    const response = await fetch(`${AUTH_API_BASE}/api/account/me`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": `Bearer ${token}`
      },
      cache: "no-store"
    });

    let data = {};
    try {
      data = await response.json();
    } catch (_) {}

    if (!response.ok || !data || data.ok === false) return false;
    return extractOwnedGameIds(data).has(GAME_ID);
  } catch (_) {
    return false;
  }
}

function isAllowedAccessResponse(data) {
  if (!data || typeof data !== "object") return false;

  return (
    data.allowed === true ||
    data.access === true ||
    data.can_play === true ||
    data.canPlay === true ||
    data.has_access === true ||
    data.hasAccess === true ||
    data.permitted === true ||
    data?.access?.allowed === true ||
    data?.game?.allowed === true
  );
}

function extractOwnedGameIds(data) {
  const ids = new Set();

  function addId(value) {
    const id = String(value || "").trim().toLowerCase();
    if (id) ids.add(id);
  }

  function readGameObject(game) {
    if (!game || typeof game !== "object") return;

    addId(game.id);
    addId(game.slug);
    addId(game.game_id);
    addId(game.gameId);
    addId(game.key);
  }

  function readArray(list) {
    if (!Array.isArray(list)) return;

    for (const item of list) {
      if (!item) continue;
      if (typeof item === "string") addId(item);
      else readGameObject(item);
    }
  }

  if (!data || typeof data !== "object") return ids;

  readArray(data.games);
  readArray(data.owned_games);
  readArray(data.ownedGames);
  readArray(data.entitlements);
  readArray(data.products);
  readArray(data.library);

  if (data.customer && typeof data.customer === "object") {
    readArray(data.customer.games);
    readArray(data.customer.owned_games);
    readArray(data.customer.ownedGames);
    readArray(data.customer.entitlements);
    readArray(data.customer.products);
    readArray(data.customer.library);
  }

  return ids;
}

function normalizeGameId(value) {
  const gameId = String(value || "").trim().toLowerCase();
  return gameId === GAME_ID ? GAME_ID : "";
}

function readFirstQueryValue(url, keys) {
  for (const key of keys) {
    const value = String(url.searchParams.get(key) || "").trim();
    if (value) return value;
  }

  return "";
}

function hasAccessQuery(url) {
  return [
    ...TOKEN_QUERY_KEYS,
    ...GAME_QUERY_KEYS,
    ...TEMP_QUERY_KEYS
  ].some(key => url.searchParams.has(key));
}

function createTemporaryDeviceToken() {
  try {
    if (crypto.randomUUID) {
      return `education_site_${crypto.randomUUID()}`;
    }
  } catch (_) {}

  try {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return "education_site_" + Array.from(bytes)
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");
  } catch (_) {}

  return `education_site_${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;
}

function buildSecureCookie(name, value, currentUrl) {
  const secure = currentUrl.protocol === "https:" ? "; Secure" : "";

  return (
    `${name}=${encodeURIComponent(value)}` +
    `; Path=/` +
    `; Max-Age=${COOKIE_MAX_AGE_SECONDS}` +
    `; SameSite=Lax` +
    `; HttpOnly` +
    secure
  );
}

function redirectToCleanUrl(currentUrl, cookiesToSet = []) {
  const target = new URL(currentUrl.toString());

  [
    ...TOKEN_QUERY_KEYS,
    ...GAME_QUERY_KEYS,
    ...TEMP_QUERY_KEYS
  ].forEach(key => target.searchParams.delete(key));

  const headers = createNoStoreHeaders();
  headers.set("Location", target.toString());
  headers.set("Referrer-Policy", "no-referrer");

  for (const cookie of cookiesToSet) {
    headers.append("Set-Cookie", cookie);
  }

  return new Response(null, {
    status: 302,
    headers
  });
}

function redirectToProductPage() {
  const headers = createNoStoreHeaders();
  headers.set("Location", PRODUCT_PAGE_URL);
  headers.set("Referrer-Policy", "no-referrer");

  return new Response(null, {
    status: 302,
    headers
  });
}

function addProtectionHeaders(response, cookiesToSet = []) {
  const headers = new Headers(response.headers);

  headers.set("Cache-Control", "private, no-store, no-cache, must-revalidate");
  headers.set("Pragma", "no-cache");
  headers.set("Expires", "0");
  headers.set("Vary", mergeVary(headers.get("Vary"), "Cookie", "Authorization"));
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "SAMEORIGIN");

  for (const cookie of cookiesToSet) {
    headers.append("Set-Cookie", cookie);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function createNoStoreHeaders() {
  const headers = new Headers();
  headers.set("Cache-Control", "private, no-store, no-cache, must-revalidate");
  headers.set("Pragma", "no-cache");
  headers.set("Expires", "0");
  headers.set("Vary", "Cookie, Authorization");
  return headers;
}

function mergeVary(currentValue, ...values) {
  const parts = String(currentValue || "")
    .split(",")
    .map(value => value.trim())
    .filter(Boolean);

  for (const value of values) {
    if (!parts.some(part => part.toLowerCase() === value.toLowerCase())) {
      parts.push(value);
    }
  }

  return parts.join(", ");
}

function parseCookies(cookieHeader) {
  const cookies = {};

  for (const part of String(cookieHeader || "").split(";")) {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex === -1) continue;

    const name = part.slice(0, separatorIndex).trim();
    const value = part.slice(separatorIndex + 1).trim();
    if (!name) continue;

    cookies[name] = decodeURIComponentSafe(value);
  }

  return cookies;
}

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch (_) {
    return value;
  }
}
