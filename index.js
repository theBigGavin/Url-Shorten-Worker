const config = {
  no_ref: "off",
  theme: "",
  cors: "on",
  unique_link: true,
  custom_link: false,
  safe_browsing_api_key: "",
  expiration_ttl: 0,
  
  captcha: {
    enabled: true,
    api_endpoint: "https://captcha.gurl.eu.org/api",
    require_on_create: true,
    require_on_access: false,
    timeout: 5000,
    fallback_on_error: true,
    max_retries: 2,
  }
}

const html404 = `<!DOCTYPE html>
<body>
  <h1>404 Not Found.</h1>
  <p>The url you visit is not found.</p>
</body>`

let response_header = {
  "content-type": "text/html;charset=UTF-8",
}

if (config.cors == "on") {
  response_header = {
    "content-type": "text/html;charset=UTF-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST",
  }
}

async function randomString(len) {
  len = len || 6;
  let $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz0123456789'; // '0123456789' 纯数字，abcdefghijklmnopqrstuvwxyz0123456789' 小写+数字
  let maxPos = $chars.length;
  let result = '';
  for (let i = 0; i < len; i++) {
    result += $chars.charAt(Math.floor(Math.random() * maxPos));
  }
  return result;
}

async function sha512(url) {
  url = new TextEncoder().encode(url)
  const url_digest = await crypto.subtle.digest({ name: "SHA-512" }, url)
  const hashArray = Array.from(new Uint8Array(url_digest));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex
}

async function checkURL(URL) {
  let str = URL;
  let Expression = /http(s)?:\/\/([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?/;
  let objExp = new RegExp(Expression);
  if (objExp.test(str) == true) {
    if (str[0] == 'h')
      return true;
    else
      return false;
  } else {
    return false;
  }
}

function getKvPutOptions() {
  const MIN_TTL = 60;
  const rawTtl = Number(config.expiration_ttl);
  const hasValidTtl = Number.isFinite(rawTtl) && rawTtl >= MIN_TTL;
  return hasValidTtl ? { expirationTtl: Math.floor(rawTtl) } : {};
}

async function save_url(URL){
    let random_key = await randomString()
    let is_exist = await LINKS.get(random_key)
    console.log(is_exist)
    if (is_exist == null) {
        await LINKS.put(random_key, URL, getKvPutOptions())
        return random_key
    }
    else {
        return save_url(URL)
    }
}

async function is_url_exist(url_sha512) {
  let is_exist = await LINKS.get(url_sha512)
  console.log(is_exist)
  if (is_exist == null) {
    return false
  } else {
    return is_exist
  }
}

async function is_url_safe(url) {
  let raw = JSON.stringify({ "client": { "clientId": "Url-Shorten-Worker", "clientVersion": "1.0.7" }, "threatInfo": { "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{ "url": url }] } });
  let requestOptions = { method: 'POST', body: raw, redirect: 'follow' };
  let result = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + config.safe_browsing_api_key, requestOptions)
  result = await result.json()
  console.log(result)
  if (Object.keys(result).length === 0) {
    return true
  } else {
    return false
  }
}

async function validateCaptchaToken(token, keepToken = false) {
  if (!config.captcha.enabled) {
    return { success: true, degraded: false };
  }
  if (!token || typeof token !== 'string' || token.length < 10) {
    return { success: false, error: 'Invalid token format' };
  }
  let lastError = null;
  const maxRetries = config.captcha.max_retries || 2;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.captcha.timeout);
      const response = await fetch(`${config.captcha.api_endpoint}/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'Url-Shorten-Worker/1.0.7',
        },
        body: JSON.stringify({ token, keepToken }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      if (response.ok) {
        const result = await response.json();
        return { success: result.success === true, degraded: false };
      }
      if (response.status === 400 || response.status === 410 || response.status === 404 || response.status === 409) {
        return { success: false, error: 'Invalid or expired token' };
      }
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error.name === 'AbortError' ? 'Timeout' : error.message;
      console.error(`CAPTCHA validation attempt ${attempt + 1} failed:`, lastError);
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
      }
    }
  }
  if (config.captcha.fallback_on_error) {
    console.warn(`CAPTCHA service degraded: ${lastError}. Allowing operation due to fallback policy.`);
    return { success: true, degraded: true };
  }
  return { success: false, error: lastError || 'CAPTCHA service unavailable' };
}

function isCaptchaRequired(operation) {
  if (!config.captcha.enabled) {
    return false;
  }
  switch (operation) {
    case 'create':
      return config.captcha.require_on_create;
    case 'access':
      return config.captcha.require_on_access;
    default:
      return false;
  }
}

async function extractCaptchaToken(request) {
  const contentType = request.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      const body = await request.clone().json();
      return body.captcha_token || body.captchaToken || body.token || null;
    } catch {
      return null;
    }
  }
  const url = new URL(request.url);
  return url.searchParams.get('captcha_token') || url.searchParams.get('token') || null;
}

async function handleRequest(request) {
  console.log(request)

  const requestURL = new URL(request.url)
  const path = requestURL.pathname

  // ========== 管理后台路由 ==========
  if (path === '/admin' || path === '/admin/') {
    return handleAdminPage()
  }

  if (path === '/admin/api/list') {
    return handleAdminList(request)
  }

  if (path === '/admin/api/delete' && request.method === 'POST') {
    return handleAdminDelete(request)
  }

  // Handle POST request - Create short link
  if (request.method === "POST") {
    let req = await request.json()
    console.log(req["url"])

    if (!await checkURL(req["url"])) {
      return new Response(JSON.stringify({
        status: 500,
        error: "Invalid URL format"
      }), {
        headers: response_header,
        status: 400
      })
    }

    if (isCaptchaRequired('create')) {
      const captchaToken = req.captcha_token || req.captchaToken || req.token;
      if (!captchaToken) {
        return new Response(JSON.stringify({
          status: 403,
          error: "CAPTCHA token required",
          captcha_required: true
        }), {
          headers: response_header,
          status: 403
        })
      }

      const validation = await validateCaptchaToken(captchaToken, false);
      if (!validation.success) {
        return new Response(JSON.stringify({
          status: 403,
          error: validation.error || "CAPTCHA verification failed",
          captcha_required: true
        }), {
          headers: response_header,
          status: 403
        })
      }
      if (validation.degraded) {
        console.warn("Request processed under CAPTCHA service degradation");
      }
    }

    let random_key
    if (config.unique_link) {
      let url_sha512 = await sha512(req["url"])
      let url_key = await is_url_exist(url_sha512)
      if (url_key) {
        random_key = url_key
      } else {
        random_key = await save_url(req["url"])
        if (random_key) {
          console.log(await LINKS.put(url_sha512, random_key, getKvPutOptions()))
        }
      }
    } else {
      random_key = await save_url(req["url"])
    }

    console.log("Generated key:", random_key)
    
    if (random_key) {
      return new Response(JSON.stringify({
        status: 200,
        key: "/" + random_key,
        short_url: "/" + random_key
      }), {
        headers: response_header,
      })
    } else {
      return new Response(JSON.stringify({
        status: 500,
        error: "Failed to generate short URL"
      }), {
        headers: response_header,
        status: 500
      })
    }
  } else if (request.method === "OPTIONS") {
    return new Response("", {
      headers: response_header,
    })
  }

  // Handle GET request - Access short link
  const shortCode = requestURL.pathname.split("/")[1]
  const params = requestURL.search

  console.log(shortCode)

  // ========== 内置 HTML 首页（带 CAPTCHA）==========
  if (!shortCode) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>URL Shortener</title>
  <script src="https://captcha.gurl.eu.org/cap.min.js"></script>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
      width: 100%;
      max-width: 500px;
      overflow: hidden;
    }
    .header {
      padding: 40px 30px 20px;
      text-align: center;
    }
    .header h1 {
      font-size: 28px;
      color: #1a1a2e;
      margin-bottom: 8px;
    }
    .header p {
      color: #666;
      font-size: 14px;
    }
    .form {
      padding: 20px 30px 30px;
    }
    .input-group {
      margin-bottom: 20px;
    }
    .input-group label {
      display: block;
      font-size: 12px;
      color: #666;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    .input-group input {
      width: 100%;
      padding: 14px 16px;
      border: 2px solid #e0e0e0;
      border-radius: 10px;
      font-size: 16px;
      transition: border-color 0.3s;
    }
    .input-group input:focus {
      outline: none;
      border-color: #667eea;
    }
    .captcha-box {
      margin: 20px 0;
      display: flex;
      justify-content: center;
      min-height: 80px;
    }
    button {
      width: 100%;
      padding: 16px;
      background: #4a7dff;
      color: white;
      border: none;
      border-radius: 10px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.3s;
    }
    button:hover:not(:disabled) {
      background: #3a6ae8;
    }
    button:disabled {
      background: #ccc;
      cursor: not-allowed;
    }
    #result {
      margin-top: 20px;
      padding: 16px;
      background: #d4edda;
      border-radius: 10px;
      display: none;
      word-break: break-all;
    }
    #result a {
      color: #155724;
      font-weight: 600;
    }
    #error {
      margin-top: 20px;
      padding: 16px;
      background: #f8d7da;
      color: #721c24;
      border-radius: 10px;
      display: none;
    }
    .footer {
      padding: 20px 30px;
      background: #f8f9fa;
      text-align: center;
      border-top: 1px solid #e0e0e0;
      display: flex;
      justify-content: center;
      gap: 20px;
    }
    .footer a {
      color: #4a7dff;
      text-decoration: none;
      font-size: 14px;
    }
    .footer a:hover {
      text-decoration: underline;
    }
    .admin-link {
      color: #666 !important;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <h1>🎁 Shorten your URLs !</h1>
      <p>Please enter the long URL to be shortened :</p>
    </div>
    
    <div class="form">
      <div class="input-group">
        <input type="url" id="url" placeholder="Example: https://example.com/" required>
      </div>
      
      <!-- CAPTCHA 组件 -->
      <div class="captcha-box">
        <cap-widget id="cap" data-cap-api-endpoint="https://captcha.gurl.eu.org/api/"></cap-widget>
      </div>
      
      <button onclick="shorten()" id="btn">Shorten it</button>
      
      <div id="result"></div>
      <div id="error"></div>
    </div>
    
    <div class="footer">
      <a href="/admin" class="admin-link">管理后台</a>
    </div>
  </div>
  
  <script>
    let captchaToken = null;
    
    // 监听 CAPTCHA 验证完成
    const widget = document.querySelector("#cap");
    widget.addEventListener("solve", function(e) {
      captchaToken = e.detail.token;
      console.log("CAPTCHA solved, token:", captchaToken);
    });
    
    async function shorten() {
      const url = document.getElementById('url').value;
      const btn = document.getElementById('btn');
      const resultDiv = document.getElementById('result');
      const errorDiv = document.getElementById('error');
      
      if (!url) {
        errorDiv.textContent = 'Please enter a URL';
        errorDiv.style.display = 'block';
        return;
      }
      
      if (!captchaToken) {
        errorDiv.textContent = 'Please complete the CAPTCHA first';
        errorDiv.style.display = 'block';
        return;
      }
      
      btn.disabled = true;
      btn.textContent = 'Shortening...';
      resultDiv.style.display = 'none';
      errorDiv.style.display = 'none';
      
      try {
        const response = await fetch('/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            url: url,
            captcha_token: captchaToken  // 携带 CAPTCHA token
          })
        });
        
        const data = await response.json();
        
        if (data.status === 200) {
          const shortUrl = window.location.origin + data.short_url;
          resultDiv.innerHTML = '<strong>Short URL:</strong><br><a href="' + shortUrl + '" target="_blank">' + shortUrl + '</a>';
          resultDiv.style.display = 'block';
          document.getElementById('url').value = '';
          // 重置 CAPTCHA
          captchaToken = null;
          widget.reset();
        } else {
          errorDiv.textContent = 'Error: ' + (data.error || 'Unknown error');
          errorDiv.style.display = 'block';
          // 如果 CAPTCHA 错误，重置
          if (data.captcha_required) {
            captchaToken = null;
            widget.reset();
          }
        }
      } catch (e) {
        errorDiv.textContent = 'Network error: ' + e.message;
        errorDiv.style.display = 'block';
      } finally {
        btn.disabled = false;
        btn.textContent = 'Shorten it';
      }
    }
    
    document.getElementById('url').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') shorten();
    });
  </script>
</body>
</html>`
    
    return new Response(html, {
      headers: { "content-type": "text/html;charset=UTF-8" }
    })
  }

  // Retrieve the target URL
  const value = await LINKS.get(shortCode)
  let location

  if (params) {
    location = value + params
  } else {
    location = value
  }
  console.log(value)

  if (location) {
    if (isCaptchaRequired('access')) {
      const captchaToken = await extractCaptchaToken(request)
      if (!captchaToken) {
        const captchaPage = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verification Required</title>
  <script src="https://captcha.gurl.eu.org/cap.min.js"></script>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; 
           display: flex; justify-content: center; align-items: center; min-height: 100vh; 
           margin: 0; background: linear-gradient(45deg, rgba(14, 46, 75, 1.000) 0.000%, rgba(14, 46, 75, 1.000) 7.692%, rgba(19, 52, 84, 1.000) 7.692%, rgba(19, 52, 84, 1.000) 15.385%, rgba(25, 58, 94, 1.000) 15.385%, rgba(25, 58, 94, 1.000) 23.077%, rgba(31, 65, 104, 1.000) 23.077%, rgba(31, 65, 104, 1.000) 30.769%, rgba(38, 72, 115, 1.000) 30.769%, rgba(38, 72, 115, 1.000) 38.462%, rgba(45, 79, 126, 1.000) 38.462%, rgba(45, 79, 126, 1.000) 46.154%, rgba(52, 86, 138, 1.000) 46.154%, rgba(52, 86, 138, 1.000) 53.846%, rgba(59, 93, 150, 1.000) 53.846%, rgba(59, 93, 150, 1.000) 61.538%, rgba(67, 101, 163, 1.000) 61.538%, rgba(67, 101, 163, 1.000) 69.231%, rgba(75, 109, 176, 1.000) 69.231%, rgba(75, 109, 176, 1.000) 76.923%, rgba(83, 117, 188, 1.000) 76.923%, rgba(83, 117, 188, 1.000) 84.615%, rgba(91, 125, 201, 1.000) 84.615%, rgba(91, 125, 201, 1.000) 92.308%, rgba(99, 134, 214, 1.000) 92.308% 100.000%) }
    .container { background: white; padding: 2rem; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.1); 
                 max-width: 400px; text-align: center; }
    h1 { color: #333; margin-bottom: 1rem; font-size: 1.5rem; }
    p { color: #666; margin-bottom: 2rem; }
    #cap { margin: 2rem 0; display: flex; justify-content: center;}
    .loading { display: none; color: #667eea; margin-top: 1rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔒 Verification Required</h1>
    <p>Please complete the CAPTCHA below to access this link.</p>
    <cap-widget id="cap" data-cap-api-endpoint="https://captcha.gurl.eu.org/api/"></cap-widget>
    <div class="loading" id="loading">Verifying and redirecting...</div>
  </div>
  <script>
    const widget = document.querySelector("#cap");
    const loading = document.getElementById("loading");
    widget.addEventListener("solve", async function (e) {
      const token = e.detail.token;
      loading.style.display = "block";
      window.location.href = window.location.pathname + "?captcha_token=" + encodeURIComponent(token);
    });
  </script>
</body>
</html>`
        return new Response(captchaPage, {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
          status: 403
        })
      }

      const validation = await validateCaptchaToken(captchaToken, false)
      if (!validation.success) {
        return new Response(`
<!DOCTYPE html>
<html>
<head><title>Verification Failed</title></head>
<body>
  <h1>❌ Verification Failed</h1>
  <p>${validation.error || 'CAPTCHA verification failed'}</p>
  <a href="${requestURL.pathname}">Try again</a>
</body>
</html>`, {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
          status: 403
        })
      }
      if (validation.degraded) {
        console.warn("Access granted under CAPTCHA service degradation")
      }
    }

    if (config.safe_browsing_api_key) {
      if (!(await is_url_safe(location))) {
        let warning_page = await fetch("https://xytom.github.io/Url-Shorten-Worker/safe-browsing.html")
        warning_page = await warning_page.text()
        warning_page = warning_page.replace(/{Replace}/gm, location)
        return new Response(warning_page, {
          headers: {
            "content-type": "text/html;charset=UTF-8",
          },
        })
      }
    }

    if (config.no_ref == "on") {
      let no_ref = await fetch("https://xytom.github.io/Url-Shorten-Worker/no-ref.html")
      no_ref = await no_ref.text()
      no_ref = no_ref.replace(/{Replace}/gm, location)
      return new Response(no_ref, {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
      })
    } else {
      return Response.redirect(location, 302)
    }
  }

  return new Response(html404, {
    headers: {
      "content-type": "text/html;charset=UTF-8",
    },
    status: 404
  })
}

addEventListener("fetch", async event => {
  event.respondWith(handleRequest(event.request))
})

// ========== 管理后台函数 ==========

async function handleAdminPage() {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>短链接管理后台</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5; 
      padding: 20px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #333; margin-bottom: 20px; }
    .stats {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 20px;
      border-radius: 10px;
      margin-bottom: 20px;
    }
    .stats h2 { font-size: 36px; margin-bottom: 5px; }
    .stats p { opacity: 0.9; }
    .login-box, .admin-box {
      background: white;
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    input[type="password"] {
      width: 100%;
      padding: 12px;
      margin: 10px 0;
      border: 1px solid #ddd;
      border-radius: 5px;
      font-size: 16px;
    }
    button {
      padding: 12px 24px;
      background: #007bff;
      color: white;
      border: none;
      border-radius: 5px;
      cursor: pointer;
      font-size: 16px;
    }
    button:hover { background: #0056b3; }
    .btn-copy {
      background: #28a745;
      padding: 6px 12px;
      font-size: 14px;
      margin-right: 8px;
    }
    .btn-copy:hover { background: #218838; }
    .btn-visit {
      background: #17a2b8;
      padding: 6px 12px;
      font-size: 14px;
      margin-right: 8px;
    }
    .btn-visit:hover { background: #138496; }
    .btn-delete {
      background: #dc3545;
      padding: 6px 12px;
      font-size: 14px;
    }
    .btn-delete:hover { background: #c82333; }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #eee;
    }
    th { 
      background: #f8f9fa; 
      font-weight: 600;
      color: #666;
      font-size: 12px;
      text-transform: uppercase;
    }
    .short-link {
      background: #e3f2fd;
      color: #1976d2;
      padding: 6px 12px;
      border-radius: 4px;
      font-family: monospace;
      font-size: 14px;
      text-decoration: none;
      display: inline-block;
    }
    .short-link:hover {
      background: #bbdefb;
    }
    .target-url {
      max-width: 350px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: #666;
      font-size: 14px;
    }
    .target-url a {
      color: #666;
      text-decoration: none;
    }
    .target-url a:hover {
      color: #007bff;
      text-decoration: underline;
    }
    #error { 
      color: #dc3545; 
      margin-top: 10px; 
      padding: 10px;
      background: #f8d7da;
      border-radius: 5px;
      display: none;
    }
    .empty-state {
      text-align: center;
      padding: 60px 20px;
      color: #999;
    }
    .hidden { display: none !important; }
    .actions {
      display: flex;
      gap: 5px;
    }
    @media (max-width: 768px) {
      .target-url { max-width: 150px; }
      .actions { flex-wrap: wrap; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔗 短链接管理后台</h1>
    
    <div id="loginSection" class="login-box">
      <h3>请输入管理密钥</h3>
      <input type="password" id="authKey" placeholder="管理密钥" onkeypress="if(event.key==='Enter')login()">
      <button onclick="login()">登录</button>
      <div id="error"></div>
    </div>
    
    <div id="adminSection" class="admin-box hidden">
      <div class="stats">
        <h2 id="totalCount">0</h2>
        <p>总短链接数</p>
      </div>
      
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
        <h3>短链接列表</h3>
        <button onclick="loadData()">🔄 刷新数据</button>
      </div>
      
      <div id="tableContainer">
        <table>
          <thead>
            <tr>
              <th style="width: 200px;">短链接</th>
              <th>目标地址</th>
              <th style="width: 180px;">操作</th>
            </tr>
          </thead>
          <tbody id="tableBody"></tbody>
        </table>
      </div>
      
      <div id="emptyState" class="empty-state hidden">
        <p>暂无短链接数据</p>
      </div>
    </div>
  </div>
  
  <script>
    const shortUrlDomain = location.origin;
    let authKey = '';
    
    function login() {
      authKey = document.getElementById('authKey').value;
      if (!authKey) {
        showError('请输入管理密钥');
        return;
      }
      loadData();
    }
    
    function showError(msg) {
      const err = document.getElementById('error');
      err.textContent = msg;
      err.style.display = 'block';
    }
    
    async function loadData() {
      try {
        const res = await fetch('/admin/api/list?key=' + encodeURIComponent(authKey));
        const data = await res.json();
        
        if (data.error) {
          showError('密钥错误，请重试');
          return;
        }
        
        document.getElementById('loginSection').classList.add('hidden');
        document.getElementById('adminSection').classList.remove('hidden');
        document.getElementById('error').style.display = 'none';
        
        document.getElementById('totalCount').textContent = data.total;
        
        const tbody = document.getElementById('tableBody');
        tbody.innerHTML = '';
        
        if (data.items.length === 0) {
          document.getElementById('tableContainer').classList.add('hidden');
          document.getElementById('emptyState').classList.remove('hidden');
          return;
        } else {
          document.getElementById('tableContainer').classList.remove('hidden');
          document.getElementById('emptyState').classList.add('hidden');
        }
        
        data.items.forEach(item => {
          const tr = document.createElement('tr');
          const fullShortUrl = shortUrlDomain + '/' + item.shortCode;
          
          tr.innerHTML = \`
            <td>
              <a href="/\${item.shortCode}" target="_blank" class="short-link">\${item.shortCode}</a>
            </td>
            <td class="target-url" title="\${item.targetUrl}">
              <a href="\${item.targetUrl}" target="_blank">\${item.targetUrl}</a>
            </td>
            <td>
              <div class="actions">
                <button class="btn-copy" onclick="copyLink('\${fullShortUrl}')">复制</button>
                <button class="btn-visit" onclick="visitLink('/\${item.shortCode}')">访问</button>
                <button class="btn-delete" onclick="deleteUrl('\${item.shortCode}')">删除</button>
              </div>
            </td>
          \`;
          tbody.appendChild(tr);
        });
        
      } catch (e) {
        showError('加载失败: ' + e.message);
      }
    }
    
    function copyLink(url) {
      navigator.clipboard.writeText(url).then(() => {
        alert('已复制到剪贴板:\\n' + url);
      });
    }
    
    function visitLink(path) {
      window.open(path, '_blank');
    }
    
    async function deleteUrl(shortCode) {
      if (!confirm('确定删除短链接 "' + shortCode + '" ?\\n\\n此操作不可恢复！')) return;
      
      try {
        const res = await fetch('/admin/api/delete?key=' + encodeURIComponent(authKey), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ shortCode })
        });
        
        const data = await res.json();
        
        if (data.success) {
          loadData();
        } else {
          alert('删除失败: ' + (data.error || '未知错误'));
        }
      } catch (e) {
        alert('删除失败: ' + e.message);
      }
    }
  </script>
</body>
</html>`
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  })
}

async function handleAdminList(request) {
  const url = new URL(request.url)
  const authKey = url.searchParams.get('key')
  
  if (authKey !== 'password') {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    })
  }
  
  const list = await LINKS.list()
  const items = []
  const seenUrls = new Set()
  
  for (const key of list.keys) {
    const value = await LINKS.get(key.name)
    if (!value) continue
    if (key.name.length === 128 && /^[a-f0-9]+$/.test(key.name)) continue
    if (seenUrls.has(key.name)) continue
    seenUrls.add(key.name)
    
    items.push({
      shortCode: key.name,
      targetUrl: value,
      created: key.created
    })
  }
  
  items.sort((a, b) => (b.created || 0) - (a.created || 0))
  
  return new Response(JSON.stringify({
    total: items.length,
    items: items
  }), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  })
}

// ========== 修复：同时删除关联的 SHA512 哈希键 ==========
async function handleAdminDelete(request) {
  const url = new URL(request.url)
  const authKey = url.searchParams.get('key')
  
  if (authKey !== 'password') {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 })
  }
  
  const { shortCode } = await request.json()
  
  // 获取目标 URL，用于计算哈希
  const targetUrl = await LINKS.get(shortCode)
  
  if (targetUrl) {
    // 删除短码
    await LINKS.delete(shortCode)
    
    // 如果启用了 unique_link，同时删除 SHA512 哈希键
    if (config.unique_link) {
      const urlHash = await sha512(targetUrl)
      // 验证这个哈希确实指向当前短码，避免误删
      const storedShortCode = await LINKS.get(urlHash)
      if (storedShortCode === shortCode) {
        await LINKS.delete(urlHash)
        console.log(`Deleted hash key: ${urlHash}`)
      }
    }
  }
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  })
}
