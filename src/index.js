export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Collect headers
    const headers = {};
    for (const [key, value] of request.headers.entries()) {
      headers[key] = value;
    }

    // Collect query params
    const query = {};
    for (const [key, value] of url.searchParams.entries()) {
      query[key] = value;
    }

    // Read body (not available for GET/HEAD)
    let body = null;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      try {
        body = await request.text();
      } catch {
        body = null;
      }
    }

    const echo = {
      method: request.method,
      url: request.url,
      path: url.pathname,
      query,
      headers,
      body: body || null,
      cf: request.cf || null,
    };

    return new Response(JSON.stringify(echo, null, 2), {
      status: 200,
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
    });
  },
};
