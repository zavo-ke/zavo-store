
const ALLOWED_ORIGINS = new Set([
  "https://zavo-store.pages.dev",
  "https://zavo-ke.github.io"
]);

const BASE_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin"
};

const ITERATIONS = 100000;
const SESSION_DAYS = 7;

const GOOGLE_CLIENT_ID =
  "776829851538-0qs24flt8ia16d6p3ir3fps9s7tmfbee.apps.googleusercontent.com";

const GOOGLE_KEYS_URL = "https://www.googleapis.com/oauth2/v3/certs";

let googleKeysCache = null;
let googleKeysExpiry = 0;

function response(data, status = 200, origin = null) {
  const headers = new Headers(BASE_HEADERS);

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
  }

  return new Response(JSON.stringify(data), { status, headers });
}

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function base64url(bytes) {
  return toBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return fromBase64(padded);
}

async function sha256(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return base64url(new Uint8Array(digest));
}

async function hashPassword(password, saltBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: saltBytes,
    iterations: ITERATIONS,
    hash: "SHA-256"
  }, key, 256);

  return toBase64(new Uint8Array(bits));
}

async function createPasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);
  return `pbkdf2$${ITERATIONS}$${toBase64(salt)}$${hash}`;
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, rounds, salt, expected] = stored.split("$");

    if (algorithm !== "pbkdf2" || Number(rounds) !== ITERATIONS) {
      return false;
    }

    const actual = await hashPassword(password, fromBase64(salt));
    const a = fromBase64(actual);
    const b = fromBase64(expected);

    if (a.length !== b.length) return false;

    let difference = 0;
    for (let i = 0; i < a.length; i++) {
      difference |= a[i] ^ b[i];
    }

    return difference === 0;
  } catch {
    return false;
  }
}

async function verifyGoogleCredential(credential) {
  const parts = credential.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid Google token.");
  }

  const header = JSON.parse(
    new TextDecoder().decode(decodeBase64Url(parts[0]))
  );

  const claims = JSON.parse(
    new TextDecoder().decode(decodeBase64Url(parts[1]))
  );

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("Unsupported Google token.");
  }

  const now = Math.floor(Date.now() / 1000);

  if (
    claims.aud !== GOOGLE_CLIENT_ID ||
    !["accounts.google.com", "https://accounts.google.com"].includes(claims.iss) ||
    typeof claims.sub !== "string" ||
    !claims.sub ||
    typeof claims.email !== "string" ||
    !claims.email ||
    claims.email_verified !== true ||
    !Number.isFinite(claims.exp) ||
    claims.exp <= now ||
    !Number.isFinite(claims.iat) ||
    claims.iat > now + 60
  ) {
    throw new Error("Google token claims are invalid.");
  }

  if (!googleKeysCache || Date.now() >= googleKeysExpiry) {
    const keyResponse = await fetch(GOOGLE_KEYS_URL);

    if (!keyResponse.ok) {
      throw new Error("Could not retrieve Google's verification keys.");
    }

    const keyData = await keyResponse.json();
    googleKeysCache = keyData.keys || [];

    const cacheControl = keyResponse.headers.get("Cache-Control") || "";
    const match = cacheControl.match(/max-age=(\d+)/);
    const maxAge = Number(match ? match[1] : 300);

    googleKeysExpiry = Date.now() + Math.min(maxAge, 3600) * 1000;
  }

  let jwk = googleKeysCache.find(key => key.kid === header.kid);

  if (!jwk) {
    googleKeysExpiry = 0;

    const keyResponse = await fetch(GOOGLE_KEYS_URL);

    if (!keyResponse.ok) {
      throw new Error("Could not refresh Google's verification keys.");
    }

    const keyData = await keyResponse.json();
    googleKeysCache = keyData.keys || [];

    const cacheControl = keyResponse.headers.get("Cache-Control") || "";
    const match = cacheControl.match(/max-age=(\d+)/);
    const maxAge = Number(match ? match[1] : 300);

    googleKeysExpiry = Date.now() + Math.min(maxAge, 3600) * 1000;
    jwk = googleKeysCache.find(key => key.kid === header.kid);
  }

  if (!jwk) {
    throw new Error("Google verification key not found.");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["verify"]
  );

  const validSignature = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    decodeBase64Url(parts[2]),
    new TextEncoder().encode(parts[0] + "." + parts[1])
  );

  if (!validSignature) {
    throw new Error("Google signature is invalid.");
  }

  return claims;
}

async function createSession(db, userId) {
  const token = base64url(
    crypto.getRandomValues(new Uint8Array(32))
  );

  const tokenHash = await sha256(token);

  const expiresAt = new Date(
    Date.now() + SESSION_DAYS * 86400000
  ).toISOString();

  await db.prepare(`
    INSERT INTO auth_sessions (token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(tokenHash, userId, expiresAt).run();

  const rolesResult = await db.prepare(
    "SELECT role FROM user_roles WHERE user_id = ?"
  ).bind(userId).all();

  const user = await db.prepare(`
    SELECT id, full_name, email
    FROM users
    WHERE id = ?
  `).bind(userId).first();

  return {
    token,
    expires_at: expiresAt,
    user: {
      id: user.id,
      full_name: user.full_name,
      email: user.email,
      roles: (rolesResult.results || []).map(row => row.role)
    }
  };
}

async function getSession(request, db) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) return null;

  const token = header.slice(7).trim();
  if (!token || token.length > 200) return null;

  const result = await db.prepare(`
    SELECT s.user_id, u.full_name, u.email, u.status
    FROM auth_sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).bind(
    await sha256(token),
    new Date().toISOString()
  ).first();

  if (!result || result.status !== "active") return null;

  const roles = await db.prepare(
    "SELECT role FROM user_roles WHERE user_id = ?"
  ).bind(result.user_id).all();

  return {
    id: result.user_id,
    full_name: result.full_name,
    email: result.email,
    roles: (roles.results || []).map(row => row.role)
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const origin = request.headers.get("Origin");

    const json = (data, status = 200) => response(data, status, origin);

    if (request.method === "OPTIONS") {
      if (origin && !ALLOWED_ORIGINS.has(origin)) {
        return new Response(null, {
          status: 403,
          headers: BASE_HEADERS
        });
      }

      const headers = new Headers(BASE_HEADERS);
      if (origin && ALLOWED_ORIGINS.has(origin)) {
        headers.set("Access-Control-Allow-Origin", origin);
      }

      return new Response(null, { status: 204, headers });
    }

    if (origin && !ALLOWED_ORIGINS.has(origin)) {
      return json({
        error: "This website is not authorised to connect to the ZAVO API."
      }, 403);
    }

    if (!env.DB) {
      return json({
        error: "The ZAVO database is not connected. Please try again later."
      }, 500);
    }

    try {
      if (path === "/" || path === "/api/health") {
        return json({ status: "ok", service: "zavo-api" });
      }

      if (path === "/api/auth/register" && request.method === "POST") {
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ error: "Please check the form and submit it again." }, 400);
        }

        const fullName = String(body.full_name || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (fullName.length < 2 || fullName.length > 100) {
          return json({
            error: "Enter your full name using 2–100 characters."
          }, 400);
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
          return json({
            error: "Enter a valid email address, for example jane@example.com."
          }, 400);
        }

        if (password.length < 12 || password.length > 128) {
          return json({
            error: "Your password must contain 12–128 characters."
          }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE lower(email) = ?"
        ).bind(email).first();

        if (existing) {
          return json({
            error: "An account may already use this email. Try logging in instead."
          }, 409);
        }

        const id = crypto.randomUUID();
        const passwordHash = await createPasswordHash(password);

        // Use a batch so the user and customer role are saved together.
        await env.DB.batch([
          env.DB.prepare(`
            INSERT INTO users (id, full_name, email, password_hash, status)
            VALUES (?, ?, ?, ?, 'active')
          `).bind(id, fullName, email, passwordHash),
          env.DB.prepare(`
            INSERT INTO user_roles (user_id, role)
            VALUES (?, 'customer')
          `).bind(id)
        ]);

        return json({
          success: true,
          message: "Your account has been created. Please log in using your email and password."
        }, 201);
      }

      if (path === "/api/auth/login" && request.method === "POST") {
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ error: "Please check your email and password fields." }, 400);
        }

        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!email || !password) {
          return json({ error: "Enter both your email address and password." }, 400);
        }

        const user = await env.DB.prepare(`
          SELECT id, full_name, email, password_hash, status
          FROM users
          WHERE lower(email) = ?
        `).bind(email).first();

        if (
          !user ||
          !user.password_hash ||
          !(await verifyPassword(password, user.password_hash))
        ) {
          return json({
            error: "The email or password is incorrect. Check both and try again."
          }, 401);
        }

        if (user.status !== "active") {
          return json({
            error: "This account is not active. Please contact ZAVO support."
          }, 403);
        }

        const session = await createSession(env.DB, user.id);

        return json({ success: true, ...session });
      }

      if (path === "/api/auth/google" && request.method === "POST") {
        let body;

        try {
          body = await request.json();
        } catch {
          return json({ error: "Google sign-in could not read the request. Please try again." }, 400);
        }

        const credential = String(body.credential || "");

        if (!credential || credential.length > 10000) {
          return json({
            error: "Google did not provide a valid sign-in credential. Try again."
          }, 400);
        }

        let claims;

        try {
          claims = await verifyGoogleCredential(credential);
        } catch (error) {
          console.error("Google verification failed:", error?.message || "Unknown error");

          return json({
            error: "Google could not verify this sign-in. Check your connection and try again."
          }, 401);
        }

        const email = String(claims.email).trim().toLowerCase();
        const googleSub = String(claims.sub);
        const fullName = String(claims.name || email.split("@")[0])
          .trim()
          .slice(0, 100);

        let account = await env.DB.prepare(`
          SELECT u.id, u.full_name, u.email, u.status
          FROM google_accounts g
          JOIN users u ON u.id = g.user_id
          WHERE g.google_sub = ?
        `).bind(googleSub).first();

        if (account && account.email.toLowerCase() !== email) {
          return json({
            error: "The Google account email has changed. Please contact ZAVO support."
          }, 403);
        }

        if (!account) {
          const existing = await env.DB.prepare(`
            SELECT id, full_name, email, status
            FROM users
            WHERE lower(email) = ?
          `).bind(email).first();

          if (existing) {
            // Google has verified this exact email. Link this Google identity
            // to the existing account rather than creating a duplicate.
            const linked = await env.DB.prepare(`
              SELECT google_sub FROM google_accounts WHERE user_id = ?
            `).bind(existing.id).first();

            if (linked && linked.google_sub !== googleSub) {
              return json({
                error: "A different Google account is already linked to this ZAVO account."
              }, 409);
            }

            if (!linked) {
              try {
                await env.DB.prepare(`
                  INSERT INTO google_accounts (google_sub, user_id, email)
                  VALUES (?, ?, ?)
                `).bind(googleSub, existing.id, email).run();
              } catch (error) {
                console.error("Google account linking failed:", error?.message || "Unknown error");
                return json({
                  error: "We couldn't link Google to this account. Please log in with your email and password."
                }, 409);
              }
            }

            account = existing;
          } else {
            const id = crypto.randomUUID();

            try {
              await env.DB.batch([
                env.DB.prepare(`
                  INSERT INTO users (id, full_name, email, password_hash, status)
                  VALUES (?, ?, ?, NULL, 'active')
                `).bind(id, fullName || email, email),
                env.DB.prepare(`
                  INSERT INTO user_roles (user_id, role)
                  VALUES (?, 'customer')
                `).bind(id),
                env.DB.prepare(`
                  INSERT INTO google_accounts (google_sub, user_id, email)
                  VALUES (?, ?, ?)
                `).bind(googleSub, id, email)
              ]);
            } catch (error) {
              console.error("Google account creation failed:", error?.message || "Unknown error");
              return json({
                error: "We couldn't create your Google account just now. Please try again."
              }, 409);
            }

            account = {
              id,
              full_name: fullName || email,
              email,
              status: "active"
            };
          }
        }

        if (account.status !== "active") {
          return json({
            error: "This account is not active. Please contact ZAVO support."
          }, 403);
        }

        const session = await createSession(env.DB, account.id);

        return json({ success: true, ...session });
      }

      if (path === "/api/auth/me" && request.method === "GET") {
        const user = await getSession(request, env.DB);

        if (!user) {
          return json({
            error: "Your session has expired. Please log in again."
          }, 401);
        }

        return json({ success: true, user });
      }

      if (path === "/api/auth/logout" && request.method === "POST") {
        const header = request.headers.get("Authorization") || "";

        if (header.startsWith("Bearer ")) {
          const token = header.slice(7).trim();

          if (token && token.length <= 200) {
            await env.DB.prepare(
              "DELETE FROM auth_sessions WHERE token_hash = ?"
            ).bind(await sha256(token)).run();
          }
        }

        return json({ success: true, message: "You have logged out." });
      }

      if (path === "/api/products" && request.method === "GET") {
        const result = await env.DB.prepare(`
          SELECT
            p.id, p.title, p.slug, p.description, p.category,
            p.price_minor, p.currency, p.stock, p.country_of_origin
          FROM products p
          INNER JOIN vendor_profiles v ON v.id = p.vendor_id
          WHERE p.status = 'published'
            AND v.status = 'active'
            AND p.stock > 0
          ORDER BY p.created_at DESC
          LIMIT 50
        `).all();

        const products = result.results || [];
        let media = [];

        if (products.length > 0) {
          const placeholders = products.map(() => "?").join(", ");
          const ids = products.map(product => product.id);

          const mediaResult = await env.DB.prepare(`
            SELECT product_id, media_url, media_type, sort_order
            FROM product_media
            WHERE product_id IN (${placeholders})
              AND media_type IN ('image', 'video')
            ORDER BY sort_order ASC
          `).bind(...ids).all();

          media = mediaResult.results || [];
        }

        const output = products.map(product => {
          const productMedia = media.filter(
            item => item.product_id === product.id
          );

          const images = productMedia
            .filter(item => item.media_type === "image")
            .map(item => item.media_url);

          const videos = productMedia
            .filter(item => item.media_type === "video")
            .map(item => item.media_url);

          const item = {
            ...product,
            images,
            videos,
            image_url: images[0] || null
          };

          if (!String(item.description || "").trim()) {
            delete item.description;
          }

          return item;
        });

        return json({
          success: true,
          count: output.length,
          products: output
        });
      }

      return json({ error: "This ZAVO API route was not found." }, 404);
    } catch (error) {
      console.error("ZAVO API error:", error?.message || "Unknown error");

      return json({
        error: "ZAVO's server encountered a problem. Please try again shortly."
      }, 500);
    }
  }
};
