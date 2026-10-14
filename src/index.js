
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
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
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
  const token = base64url(crypto.getRandomValues(new Uint8Array(32)));
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
    SELECT id, full_name, email FROM users WHERE id = ?
  `).bind(userId).first();

  if (!user) {
    throw new Error("Could not load the user account.");
  }

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
  `).bind(await sha256(token), new Date().toISOString()).first();

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

async function requireAdmin(request, db) {
  const user = await getSession(request, db);

  if (!user) {
    return {
      ok: false,
      status: 401,
      error: "Please log in with your administrator account."
    };
  }

  if (!user.roles.includes("admin")) {
    return {
      ok: false,
      status: 403,
      error: "Access denied. Administrator permission is required."
    };
  }

  return { ok: true, user };
}

async function readBody(request) {
  try {
    const body = await request.json();

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return null;
    }

    return body;
  } catch {
    return null;
  }
}

function makeSlug(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 100);
}

/*
 * IMPORTANT:
 * Do not create or alter audit_logs here.
 * The existing ZAVO D1 table uses entity_type, entity_id and details_json.
 */
async function logAdminAction(
  db,
  adminId,
  action,
  entityType,
  entityId,
  details = {}
) {
  try {
    await db.prepare(`
      INSERT INTO audit_logs
        (id, actor_user_id, action, entity_type, entity_id, details_json)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      crypto.randomUUID(),
      adminId,
      action,
      entityType,
      entityId || null,
      JSON.stringify(details)
    ).run();
  } catch (error) {
    // Audit failure must not undo an already completed main action.
    console.error(
      "Admin audit logging failed:",
      error?.message || "Unknown error"
    );
  }
}

async function getAdmin(request, db, json) {
  const auth = await requireAdmin(request, db);

  if (!auth.ok) {
    return {
      user: null,
      response: json({ success: false, error: auth.error }, auth.status)
    };
  }

  return { user: auth.user, response: null };
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
        success: false,
        error: "This website is not authorised to connect to the ZAVO API."
      }, 403);
    }

    if (!env.DB) {
      return json({
        success: false,
        error: "The ZAVO database is not connected."
      }, 500);
    }

    const db = env.DB;

    try {
      if (path === "/" || path === "/api/health") {
        return json({ status: "ok", service: "zavo-api" });
      }

      // ---------------------------------------------------------
      // CUSTOMER REGISTRATION
      // ---------------------------------------------------------
      if (path === "/api/auth/register" && request.method === "POST") {
        const body = await readBody(request);

        if (!body) {
          return json({
            error: "Please check the form and submit it again."
          }, 400);
        }

        const fullName = String(body.full_name || "").trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");
        const confirmPassword = String(body.confirm_password || "");

        if (fullName.length < 2 || fullName.length > 100) {
          return json({
            error: "Enter your full name using 2–100 characters."
          }, 400);
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
          return json({ error: "Enter a valid email address." }, 400);
        }

        if (password.length < 12 || password.length > 128) {
          return json({
            error: "Your password must contain 12–128 characters."
          }, 400);
        }

        /*
         * If the storefront sends confirm_password, verify it.
         * This does not replace email verification, which requires
         * a configured email delivery service and verification tokens.
         */
        if (confirmPassword && password !== confirmPassword) {
          return json({ error: "The passwords do not match." }, 400);
        }

        const existing = await db.prepare(
          "SELECT id FROM users WHERE lower(email) = ?"
        ).bind(email).first();

        if (existing) {
          return json({
            error: "An account may already use this email. Try logging in instead."
          }, 409);
        }

        const id = crypto.randomUUID();
        const passwordHash = await createPasswordHash(password);

        await db.batch([
          db.prepare(`
            INSERT INTO users (id, full_name, email, password_hash, status)
            VALUES (?, ?, ?, ?, 'active')
          `).bind(id, fullName, email, passwordHash),
          db.prepare(`
            INSERT INTO user_roles (user_id, role)
            VALUES (?, 'customer')
          `).bind(id)
        ]);

        return json({
          success: true,
          message: "Your account has been created. Please log in."
        }, 201);
      }

      // ---------------------------------------------------------
      // EMAIL LOGIN
      // ---------------------------------------------------------
      if (path === "/api/auth/login" && request.method === "POST") {
        const body = await readBody(request);

        if (!body) {
          return json({
            error: "Please check your email and password fields."
          }, 400);
        }

        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!email || !password) {
          return json({
            error: "Enter both your email address and password."
          }, 400);
        }

        const user = await db.prepare(`
          SELECT id, full_name, email, password_hash, status
          FROM users
          WHERE lower(email) = ?
        `).bind(email).first();

        if (!user || !user.password_hash ||
            !(await verifyPassword(password, user.password_hash))) {
          return json({
            error: "The email or password is incorrect."
          }, 401);
        }

        if (user.status !== "active") {
          return json({
            error: "This account is not active. Please contact ZAVO support."
          }, 403);
        }

        return json({
          success: true,
          ...(await createSession(db, user.id))
        });
      }

      // ---------------------------------------------------------
      // GOOGLE SIGN-IN
      // ---------------------------------------------------------
      if (path === "/api/auth/google" && request.method === "POST") {
        const body = await readBody(request);
        const credential = String(body?.credential || "");

        if (!credential || credential.length > 10000) {
          return json({
            error: "Google did not provide a valid credential."
          }, 400);
        }

        let claims;

        try {
          claims = await verifyGoogleCredential(credential);
        } catch (error) {
          console.error(
            "Google verification failed:",
            error?.message || "Unknown error"
          );

          return json({
            error: "Google could not verify this sign-in. Please try again."
          }, 401);
        }

        const email = String(claims.email).trim().toLowerCase();
        const googleSub = String(claims.sub);
        const fullName = String(claims.name || email.split("@")[0])
          .trim()
          .slice(0, 100);

        let account = await db.prepare(`
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
          const existing = await db.prepare(`
            SELECT id, full_name, email, status
            FROM users
            WHERE lower(email) = ?
          `).bind(email).first();

          if (existing) {
            const linked = await db.prepare(
              "SELECT google_sub FROM google_accounts WHERE user_id = ?"
            ).bind(existing.id).first();

            if (linked && linked.google_sub !== googleSub) {
              return json({
                error: "A different Google account is already linked to this ZAVO account."
              }, 409);
            }

            if (!linked) {
              await db.prepare(`
                INSERT INTO google_accounts (google_sub, user_id, email)
                VALUES (?, ?, ?)
              `).bind(googleSub, existing.id, email).run();
            }

            account = existing;
          } else {
            const id = crypto.randomUUID();

            await db.batch([
              db.prepare(`
                INSERT INTO users (id, full_name, email, password_hash, status)
                VALUES (?, ?, ?, NULL, 'active')
              `).bind(id, fullName || email, email),
              db.prepare(`
                INSERT INTO user_roles (user_id, role)
                VALUES (?, 'customer')
              `).bind(id),
              db.prepare(`
                INSERT INTO google_accounts (google_sub, user_id, email)
                VALUES (?, ?, ?)
              `).bind(googleSub, id, email)
            ]);

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

        return json({
          success: true,
          ...(await createSession(db, account.id))
        });
      }

      // ---------------------------------------------------------
      // CURRENT USER AND LOGOUT
      // ---------------------------------------------------------
      if (path === "/api/auth/me" && request.method === "GET") {
        const user = await getSession(request, db);

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
            await db.prepare(
              "DELETE FROM auth_sessions WHERE token_hash = ?"
            ).bind(await sha256(token)).run();
          }
        }

        return json({
          success: true,
          message: "You have logged out."
        });
      }

      // =========================================================
      // ADMIN: LIST PRODUCTS
      // =========================================================
      if (path === "/api/admin/products" && request.method === "GET") {
        const admin = await getAdmin(request, db, json);
        if (admin.response) return admin.response;

        const result = await db.prepare(`
          SELECT
            p.id, p.vendor_id, p.title, p.slug, p.description,
            p.category, p.sku, p.cost_minor, p.price_minor,
            p.currency, p.stock, p.status, p.country_of_origin,
            p.return_policy, p.created_at, v.store_name,
            v.status AS vendor_status
          FROM products p
          LEFT JOIN vendor_profiles v ON v.id = p.vendor_id
          ORDER BY p.created_at DESC
          LIMIT 200
        `).all();

        return json({
          success: true,
          products: result.results || []
        });
      }

      // =========================================================
      // ADMIN: CREATE PRODUCT
      // =========================================================
      if (path === "/api/admin/products" && request.method === "POST") {
        const admin = await getAdmin(request, db, json);
        if (admin.response) return admin.response;

        const body = await readBody(request);
        if (!body) return json({ error: "Invalid product details." }, 400);

        const title = String(body.title || "").trim();
        const description = String(body.description || "").trim();
        const category = String(body.category || "").trim();
        const currency = String(body.currency || "KES").trim().toUpperCase();
        const cost = Number(body.cost_minor ?? 0);
        const price = Number(body.price_minor);
        const stock = Number(body.stock ?? 0);
        const status = String(body.status || "draft");
        const vendorId = String(body.vendor_id || "").trim();
        const country = String(body.country_of_origin || "").trim();
        const returnPolicy = String(body.return_policy || "").trim();
        const sku = String(body.sku || "").trim();

        if (!title || title.length > 200 ||
            !category || category.length > 100) {
          return json({
            error: "Enter a product title and category."
          }, 400);
        }

        if (!Number.isSafeInteger(price) || price < 0 ||
            !Number.isSafeInteger(cost) || cost < 0 ||
            !Number.isSafeInteger(stock) || stock < 0) {
          return json({
            error: "Price, cost and stock must be valid non-negative whole numbers."
          }, 400);
        }

        if (!["KES", "USD"].includes(currency)) {
          return json({
            error: "Supported currencies are KES and USD."
          }, 400);
        }

        if (!["draft", "published"].includes(status)) {
          return json({
            error: "Product status must be draft or published."
          }, 400);
        }

        let vendor;

        if (vendorId) {
          vendor = await db.prepare(`
            SELECT v.id
            FROM vendor_profiles v
            JOIN users u ON u.id = v.user_id
            WHERE v.id = ?
              AND v.status = 'active'
              AND u.status = 'active'
          `).bind(vendorId).first();
        } else {
          vendor = await db.prepare(`
            SELECT v.id
            FROM vendor_profiles v
            JOIN users u ON u.id = v.user_id
            WHERE v.status = 'active'
              AND u.status = 'active'
            ORDER BY v.created_at ASC
            LIMIT 1
          `).first();
        }

        if (!vendor) {
          return json({
            error: "No approved active vendor was found. Approve a vendor first."
          }, 409);
        }

        const id = crypto.randomUUID();
        const slug = `${makeSlug(title) || "product"}-${id.slice(0, 8)}`;

        await db.prepare(`
          INSERT INTO products (
            id, vendor_id, title, slug, description, category, sku,
            cost_minor, price_minor, currency, stock, status,
            country_of_origin, return_policy
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          id, vendor.id, title, slug, description, category,
          sku || null, cost, price, currency, stock, status,
          country || null, returnPolicy || null
        ).run();

        await logAdminAction(
          db, admin.user.id, "product_created", "product", id,
          { title, status }
        );

        return json({
          success: true,
          message: "Product created.",
          product_id: id
        }, 201);
      }

      // =========================================================
      // ADMIN: EDIT PRODUCT
      // =========================================================
      if (path === "/api/admin/products/update" && request.method === "POST") {
        const admin = await getAdmin(request, db, json);
        if (admin.response) return admin.response;

        const body = await readBody(request);
        if (!body) return json({ error: "Invalid product details." }, 400);

        const id = String(body.id || "").trim();
        const title = String(body.title || "").trim();
        const description = String(body.description || "").trim();
        const category = String(body.category || "").trim();
        const currency = String(body.currency || "KES").trim().toUpperCase();
        const cost = Number(body.cost_minor ?? 0);
        const price = Number(body.price_minor);
        const stock = Number(body.stock ?? 0);
        const country = String(body.country_of_origin || "").trim();
        const returnPolicy = String(body.return_policy || "").trim();
        const sku = String(body.sku || "").trim();

        if (!id || !title || title.length > 200 ||
            !category || category.length > 100) {
          return json({
            error: "Product ID, title and category are required."
          }, 400);
        }

        if (!Number.isSafeInteger(price) || price < 0 ||
            !Number.isSafeInteger(cost) || cost < 0 ||
            !Number.isSafeInteger(stock) || stock < 0 ||
            !["KES", "USD"].includes(currency)) {
          return json({
            error: "Check the product price, cost, stock and currency."
          }, 400);
        }

        const existing = await db.prepare(
          "SELECT id FROM products WHERE id = ?"
        ).bind(id).first();

        if (!existing) {
          return json({ error: "Product not found." }, 404);
        }

        await db.prepare(`
          UPDATE products
          SET title = ?, description = ?, category = ?, sku = ?,
              cost_minor = ?, price_minor = ?, currency = ?, stock = ?,
              country_of_origin = ?, return_policy = ?
          WHERE id = ?
        `).bind(
          title, description, category, sku || null, cost, price,
          currency, stock, country || null, returnPolicy || null, id
        ).run();

        await logAdminAction(
          db, admin.user.id, "product_updated", "product", id, { title }
        );

        return json({
          success: true,
          message: "Product updated."
        });
      }

      // =========================================================
      // ADMIN: PUBLISH OR UNPUBLISH PRODUCT
      // =========================================================
      if (path === "/api/admin/products/status" && request.method === "POST") {
        const admin = await getAdmin(request, db, json);
        if (admin.response) return admin.response;

        const body = await readBody(request);
        const id = String(body?.id || "").trim();
        const status = String(body?.status || "");

        if (!id || !["draft", "published"].includes(status)) {
          return json({
            error: "Provide a product ID and status of draft or published."
          }, 400);
        }

        const product = await db.prepare(`
          SELECT p.id, p.vendor_id, v.status AS vendor_status,
                 u.status AS account_status
          FROM products p
          JOIN vendor_profiles v ON v.id = p.vendor_id
          JOIN users u ON u.id = v.user_id
          WHERE p.id = ?
        `).bind(id).first();

        if (!product) {
          return json({ error: "Product not found." }, 404);
        }

        if (
          status === "published" &&
          (product.vendor_status !== "active" ||
           product.account_status !== "active")
        ) {
          return json({
            error: "This product cannot be published until its vendor and user account are active."
          }, 409);
        }

        await db.prepare(
          "UPDATE products SET status = ? WHERE id = ?"
        ).bind(status, id).run();

        await logAdminAction(
          db, admin.user.id, "product_status_changed", "product", id,
          { status }
        );

        return json({
          success: true,
          message: `Product status changed to ${status}.`
        });
      }

      // =========================================================
      // ADMIN: DELETE PRODUCT SAFELY
      // =========================================================
      if (path === "/api/admin/products/delete" && request.method === "POST") {
        const admin = await getAdmin(request, db, json);
        if (admin.response) return admin.response;

        const body = await readBody(request);
        const id = String(body?.id || "").trim();

        if (!id) {
          return json({ error: "Product ID is required." }, 400);
        }

        const product = await db.prepare(
          "SELECT id, title FROM products WHERE id = ?"
        ).bind(id).first();

        if (!product) {
          return json({ error: "Product not found." }, 404);
        }

        const orderHistory = await db.prepare(
          "SELECT id FROM order_items WHERE product_id = ? LIMIT 1"
        ).bind(id).first();

        if (orderHistory) {
          return json({
            success: false,
            error: "This product is linked to order history and cannot be deleted. Change its status to draft to remove it from the public catalogue."
          }, 409);
        }

        /*
         * Both operations are batched. The order-history check above
         * protects records referenced by existing order_items.
         */
        await db.batch([
          db.prepare(
            "DELETE FROM product_media WHERE product_id = ?"
          ).bind(id),
          db.prepare(
            "DELETE FROM products WHERE id = ?"
          ).bind(id)
        ]);

        await logAdminAction(
          db, admin.user.id, "product_deleted", "product", id,
          { title: product.title }
        );

        return json({
          success: true,
          message: "Product and its media records have been deleted."
        });
      }

      // =========================================================
      // ADMIN: LIST VENDORS
      // =========================================================
      if (path === "/api/admin/vendors" && request.method === "GET") {
        const admin = await getAdmin(request, db, json);
        if (admin.response) return admin.response;

        const result = await db.prepare(`
          SELECT
            v.id AS vendor_id,
            v.user_id,
            v.store_name,
            v.country,
            v.status AS vendor_status,
            v.created_at AS vendor_created_at,
            u.full_name,
            u.email,
            u.phone,
            u.status AS account_status
          FROM vendor_profiles v
          LEFT JOIN users u ON u.id = v.user_id
          ORDER BY v.created_at DESC
          LIMIT 200
        `).all();

        return json({
          success: true,
          vendors: result.results || []
        });
      }

      // =========================================================
      // ADMIN: APPROVE, WARN, SUSPEND OR RESTORE VENDOR
      // =========================================================
      if (path === "/api/admin/vendors/action" && request.method === "POST") {
        const admin = await getAdmin(request, db, json);
        if (admin.response) return admin.response;

        const body = await readBody(request);
        const vendorId = String(body?.vendor_id || "").trim();
        const action = String(body?.action || "").trim().toLowerCase();
        const reason = String(body?.reason || "").trim().slice(0, 1000);

        const allowedActions = [
          "approve", "warn", "suspend", "restore"
        ];

        if (!vendorId || !allowedActions.includes(action)) {
          return json({
            error: "Provide a vendor ID and action: approve, warn, suspend or restore. Banning is not supported by the current database status rules; use suspension instead."
          }, 400);
        }

        if (["warn", "suspend"].includes(action) && !reason) {
          return json({
            error: "Enter a reason so the decision can be recorded."
          }, 400);
        }

        const vendor = await db.prepare(`
          SELECT v.id, v.user_id, v.store_name, v.status,
                 u.status AS account_status
          FROM vendor_profiles v
          LEFT JOIN users u ON u.id = v.user_id
          WHERE v.id = ?
        `).bind(vendorId).first();

        if (!vendor) {
          return json({ error: "Vendor account not found." }, 404);
        }

        if (!vendor.user_id) {
          return json({
            error: "This vendor has no linked user account and cannot be changed."
          }, 409);
        }

        if (vendor.user_id === admin.user.id && action !== "warn") {
          return json({
            error: "You cannot suspend or change your own administrator account through vendor controls."
          }, 403);
        }

        if (action === "approve") {
          await db.batch([
            db.prepare(`
              UPDATE vendor_profiles SET status = 'active' WHERE id = ?
            `).bind(vendorId),
            db.prepare(`
              UPDATE users SET status = 'active' WHERE id = ?
            `).bind(vendor.user_id)
          ]);
        }

        if (action === "warn") {
          await logAdminAction(
            db, admin.user.id, "vendor_warning_issued", "vendor", vendorId,
            { store_name: vendor.store_name, reason }
          );
        }

        if (action === "suspend") {
          await db.batch([
            db.prepare(`
              UPDATE vendor_profiles SET status = 'suspended' WHERE id = ?
            `).bind(vendorId),
            db.prepare(`
              UPDATE users SET status = 'suspended' WHERE id = ?
            `).bind(vendor.user_id),
            db.prepare(`
              DELETE FROM auth_sessions WHERE user_id = ?
            `).bind(vendor.user_id)
          ]);
        }

        if (action === "restore") {
          await db.batch([
            db.prepare(`
              UPDATE vendor_profiles SET status = 'active' WHERE id = ?
            `).bind(vendorId),
            db.prepare(`
              UPDATE users SET status = 'active' WHERE id = ?
            `).bind(vendor.user_id)
          ]);
        }

        if (action !== "warn") {
          await logAdminAction(
            db, admin.user.id, `vendor_${action}`, "vendor", vendorId,
            {
              store_name: vendor.store_name,
              previous_vendor_status: vendor.status,
              previous_account_status: vendor.account_status,
              reason
            }
          );
        }

        const messages = {
          approve: "Vendor approved. The vendor account is active.",
          warn: "Warning recorded in the administrator action log.",
          suspend: "Vendor suspended. Their sessions have been revoked and their listings are hidden.",
          restore: "Vendor account restored."
        };

        return json({
          success: true,
          action,
          message: messages[action]
        });
      }

      // =========================================================
      // PUBLIC PRODUCT CATALOGUE
      // =========================================================
      if (path === "/api/products" && request.method === "GET") {
        const result = await db.prepare(`
          SELECT
            p.id, p.title, p.slug, p.description, p.category,
            p.price_minor, p.currency, p.stock, p.country_of_origin
          FROM products p
          INNER JOIN vendor_profiles v ON v.id = p.vendor_id
          INNER JOIN users u ON u.id = v.user_id
          WHERE p.status = 'published'
            AND v.status = 'active'
            AND u.status = 'active'
            AND p.stock > 0
          ORDER BY p.created_at DESC
          LIMIT 50
        `).all();

        const products = result.results || [];
        let media = [];

        if (products.length > 0) {
          const placeholders = products.map(() => "?").join(", ");
          const ids = products.map(product => product.id);

          const mediaResult = await db.prepare(`
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

      return json({
        success: false,
        error: "This ZAVO API route was not found."
      }, 404);

    } catch (error) {
      console.error(
        "ZAVO API error:",
        error?.message || "Unknown error"
      );

      return json({
        success: false,
        error: "ZAVO's server encountered a problem. Please try again shortly."
      }, 500);
    }
  }
};
