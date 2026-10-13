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

    if (url.pathname === "/api/health" && request.method === "GET") {
      return Response.json(
        { status: "ok", service: "zavo-api" },
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
            p.country_of_origin
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

        return Response.json(
          {
            success: true,
            count: output.length,
            products: output
          },
          { headers }
        );
      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Unable to retrieve products. Check the database configuration."
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
