
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const headers = {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    if (url.pathname === "/api/health") {
      return Response.json(
        { status: "ok", service: "zavo-api-v2" },
        { headers }
      );
    }

    if (url.pathname === "/api/products" && request.method === "GET") {
      try {
        const result = await env.DB.prepare(`
          SELECT
            p.id,
            p.title,
            p.slug,
            p.description,
            p.category,
            p.price_minor,
            p.currency,
            p.stock,
            p.country_of_origin,
            (
              SELECT pm.media_url
              FROM product_media pm
              WHERE pm.product_id = p.id
                AND pm.media_type = 'image'
              ORDER BY pm.sort_order ASC
              LIMIT 1
            ) AS image_url
          FROM products p
          INNER JOIN vendor_profiles v ON v.id = p.vendor_id
          WHERE p.status = 'published'
            AND v.status = 'active'
            AND p.stock > 0
          ORDER BY p.created_at DESC
          LIMIT 50
        `).all();

        return Response.json(
          {
            success: true,
            count: result.results.length,
            products: result.results
          },
          { headers }
        );
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Unable to retrieve products. Check the database schema."
          },
          { status: 500, headers }
        );
      }
    }

    return Response.json(
      { error: "Route not found" },
      { status: 404, headers }
    );
  }
};
