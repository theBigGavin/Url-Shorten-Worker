const config = {
  no_ref: "off", //Control the HTTP referrer header, if you want to create an anonymous link that will hide the HTTP Referer header, please set to "on" .
  theme:"theme/captcha",//Homepage theme, use the empty value for default theme. To use urlcool theme, please fill with "theme/urlcool" . If you need captcha feature, you need to use captcha theme.
  cors: "on",//Allow Cross-origin resource sharing for API requests.
  unique_link:true,//If it is true, the same long url will be shorten into the same short url
  custom_link:false,//Allow users to customize the short url.
  safe_browsing_api_key: "", //Enter Google Safe Browsing API Key to enable url safety check before redirect.
  expiration_ttl: 0, // Short link expiration time in seconds. 86400 = 24 hours. Set to 0 for no expiration.
  
  // CAPTCHA Configuration
  captcha: {
    enabled: true, // Master switch for CAPTCHA service
    api_endpoint: "https://captcha.gurl.eu.org/api", // CAP Worker API endpoint
    require_on_create: true, // Require CAPTCHA when creating short links
    require_on_access: false, // Require CAPTCHA when accessing short links
    timeout: 5000, // API request timeout in milliseconds
    fallback_on_error: true, // Allow operations when CAPTCHA service is down
    max_retries: 2, // Maximum retry attempts for CAPTCHA API calls
  }
  }
  
  const html404 = `<!DOCTYPE html>
  <body>
    <h1>404 Not Found.</h1>
    <p>The url you visit is not found.</p>
    <a href="https://github.com/xyTom/Url-Shorten-Worker/" target="_self">Fork me on GitHub</a>
  </body>`
  
  let response_header={
    "content-type": "text/html;charset=UTF-8",
  } 
  
  if (config.cors=="on"){
    response_header={
    "content-type": "text/html;charset=UTF-8",
    "Access-Control-Allow-Origin":"*",
    "Access-Control-Allow-Methods": "POST",
    }
  }
  
  async function randomString(len) {
  　　len = len || 6;
  　　let $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';    /****默认去掉了容易混淆的字符oOLl,9gq,Vv,Uu,I1****/
  　　let maxPos = $chars.length;
  　　let result = '';
  　　for (let i = 0; i < len; i++) {
  　　　　result += $chars.charAt(Math.floor(Math.random() * maxPos));
  　　}
  　　return result;
  }
  
  async function sha512(url){
      url = new TextEncoder().encode(url)
  
      const url_digest = await crypto.subtle.digest(
        {
          name: "SHA-512",
        },
        url, // The data you want to hash as an ArrayBuffer
      )
      const hashArray = Array.from(new Uint8Array(url_digest)); // convert buffer to byte array
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      //console.log(hashHex)
      return hashHex
  }
  async function checkURL(URL){
      let str=URL;
      let Expression=/http(s)?:\/\/([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?/;
      let objExp=new RegExp(Expression);
      if(objExp.test(str)==true){
        if (str[0] == 'h')
          return true;
        else
          return false;
      }else{
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
      let random_key=await randomString()
      let is_exist=await LINKS.get(random_key)
      console.log(is_exist)
      if (is_exist == null) {
          return await LINKS.put(random_key, URL, getKvPutOptions()), random_key
      }
      else
          return save_url(URL)
  }
  async function is_url_exist(url_sha512){
    let is_exist = await LINKS.get(url_sha512)
    console.log(is_exist)
    if (is_exist == null) {
      return false
    }else{
      return is_exist
    }
  }
  async function is_url_safe(url){
  
    let raw = JSON.stringify({"client":{"clientId":"Url-Shorten-Worker","clientVersion":"1.0.7"},"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING","POTENTIALLY_HARMFUL_APPLICATION","UNWANTED_SOFTWARE"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":url}]}});
  
    let requestOptions = {
      method: 'POST',
      body: raw,
      redirect: 'follow'
    };
  
    let result = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+config.safe_browsing_api_key, requestOptions)
    result = await result.json()
    console.log(result)
    if (Object.keys(result).length === 0){
      return true
    }else{
      return false
    }
  }
  
  // ============ CAPTCHA Service Integration ============
  
  /**
   * Validates CAPTCHA token with retry and fallback mechanism
   * @param {string} token - The CAPTCHA token to validate
   * @param {boolean} keepToken - Whether to keep the token for reuse
   * @returns {Promise<{success: boolean, error?: string, degraded?: boolean}>}
   */
  async function validateCaptchaToken(token, keepToken = false) {
    // If CAPTCHA is disabled, always return success
    if (!config.captcha.enabled) {
      return { success: true, degraded: false };
    }
  
    // Validate token format
    if (!token || typeof token !== 'string' || token.length < 10) {
      return { success: false, error: 'Invalid token format' };
    }
  
    let lastError = null;
    const maxRetries = config.captcha.max_retries || 2;
  
    // Retry mechanism for resilience
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
  
        // Handle various HTTP status codes
        if (response.ok) {
          const result = await response.json();
          return { success: result.success === true, degraded: false };
        }
  
        // Handle specific error codes
        if (response.status === 400 || response.status === 410 || response.status === 404 || response.status === 409) {
          // Client error, no need to retry
          return { success: false, error: 'Invalid or expired token' };
        }
  
        lastError = `HTTP ${response.status}`;
      } catch (error) {
        lastError = error.name === 'AbortError' ? 'Timeout' : error.message;
        console.error(`CAPTCHA validation attempt ${attempt + 1} failed:`, lastError);
  
        // Exponential backoff before retry (except on last attempt)
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 100));
        }
      }
    }
  
    // Service degradation: if fallback is enabled, allow operation
    if (config.captcha.fallback_on_error) {
      console.warn(`CAPTCHA service degraded: ${lastError}. Allowing operation due to fallback policy.`);
      return { success: true, degraded: true };
    }
  
    return { success: false, error: lastError || 'CAPTCHA service unavailable' };
  }
  
  /**
   * Checks if CAPTCHA is required for the current operation
   * @param {string} operation - 'create' or 'access'
   * @returns {boolean}
   */
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
  
  /**
   * Extracts CAPTCHA token from request
   * @param {Request} request - The incoming request
   * @returns {Promise<string|null>}
   */
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
  
    // Try to extract from URL parameters
    const url = new URL(request.url);
    return url.searchParams.get('captcha_token') || url.searchParams.get('token') || null;
  }
  
  // ============ End CAPTCHA Service Integration ============
  async function handleRequest(request) {
    console.log(request)

    const requestURL = new URL(request.url)
    const path = requestURL.pathname
    
    // ========== 管理后台路由 ==========
    
    // 管理后台页面
    if (path === '/admin' || path === '/admin/') {
      return handleAdminPage()
    }
    
    // 管理 API：获取列表
    if (path === '/admin/api/list') {
      return handleAdminList(request)
    }
    
    // 管理 API：删除
    if (path === '/admin/api/delete' && request.method === 'POST') {
      return handleAdminDelete(request)
    }
    
    // Handle POST request - Create short link
    if (request.method === "POST") {
      let req = await request.json()
      console.log(req["url"])
      
      // Validate URL format
      if (!await checkURL(req["url"])) {
        return new Response(JSON.stringify({
          status: 500,
          error: "Invalid URL format"
        }), {
          headers: response_header,
          status: 400
        })
      }
  
      // CAPTCHA validation for link creation
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
  
        // Log if service is degraded
        if (validation.degraded) {
          console.warn("Request processed under CAPTCHA service degradation");
        }
      }
  
      // Process short link creation
      let stat, random_key
      if (config.unique_link) {
        let url_sha512 = await sha512(req["url"])
        let url_key = await is_url_exist(url_sha512)
        if (url_key) {
          random_key = url_key
        } else {
          stat, random_key = await save_url(req["url"])
          if (typeof(stat) == "undefined") {
            console.log(await LINKS.put(url_sha512, random_key, getKvPutOptions()))
          }
        }
      } else {
        stat, random_key = await save_url(req["url"])
      }
      
      console.log(stat)
      if (typeof(stat) == "undefined") {
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
          error: "Reached KV write limitation"
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
    path = requestURL.pathname.split("/")[1]
    const params = requestURL.search
  
    console.log(path)
    
    // Serve homepage
    if (!path) {
      const html = await fetch("https://xytom.github.io/Url-Shorten-Worker/" + config.theme + "/index.html")
      
      return new Response(await html.text(), {
        headers: {
          "content-type": "text/html;charset=UTF-8",
        },
      })
    }
  
    // Retrieve the target URL
    const value = await LINKS.get(path)
    let location
  
    if (params) {
      location = value + params
    } else {
      location = value
    }
    console.log(value)
  
    if (location) {
      // CAPTCHA validation for link access
      if (isCaptchaRequired('access')) {
        const captchaToken = await extractCaptchaToken(request)
        
        if (!captchaToken) {
          // Return CAPTCHA challenge page
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
        
        // Redirect with token
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
  
      // Safe browsing check
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
  
      // Redirect to target URL
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
    
    // If request not in kv, return 404
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

// ========== 管理后台函数（添加在 handleRequest 后面）==========

// 1. 管理页面 HTML（优化版）
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
    .empty-state svg {
      width: 64px;
      height: 64px;
      margin-bottom: 20px;
      opacity: 0.3;
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
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>
        </svg>
        <p>暂无短链接数据</p>
      </div>
    </div>
  </div>
  
  <script>
    // 从当前域名推断短链接域名
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
        
        // 隐藏登录框，显示管理界面
        document.getElementById('loginSection').classList.add('hidden');
        document.getElementById('adminSection').classList.remove('hidden');
        document.getElementById('error').style.display = 'none';
        
        // 更新统计
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
        
        // 渲染列表
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
          loadData(); // 刷新列表
        } else {
          alert('删除失败: ' + (data.error || '未知错误'));
        }
      } catch (e) {
        alert('删除失败: ' + e.message);
      }
    }
    
    // 支持回车登录
    document.getElementById('authKey')?.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') login();
    });
  </script>
</body>
</html>`
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html;charset=UTF-8' }
  })
}

// 2. API：获取短链接列表（过滤掉哈希键）
async function handleAdminList(request) {
  const url = new URL(request.url)
  const authKey = url.searchParams.get('key')
  
  if (authKey !== 'your-secret-key') {  // ← 修改为你的密码
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    })
  }
  
  const list = await LINKS.list()
  const items = []
  const seenUrls = new Set() // 用于去重
  
  for (const key of list.keys) {
    const value = await LINKS.get(key.name)
    
    // 跳过无效的条目
    if (!value) continue
    
    // 过滤掉 SHA512 哈希键（用于 unique_link 功能）
    // 哈希键通常是 128 位的十六进制字符串（128字符）
    if (key.name.length === 128 && /^[a-f0-9]+$/.test(key.name)) {
      continue
    }
    
    // 跳过重复的短码（理论上不应发生）
    if (seenUrls.has(key.name)) continue
    seenUrls.add(key.name)
    
    items.push({
      shortCode: key.name,
      targetUrl: value,
      created: key.created
    })
  }
  
  // 按创建时间倒序排列（新的在前）
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

// 3. API：删除短链接（保持不变）
async function handleAdminDelete(request) {
  const url = new URL(request.url)
  const authKey = url.searchParams.get('key')
  
  if (authKey !== 'your-secret-key') {  // ← 修改为你的密码
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 })
  }
  
  const { shortCode } = await request.json()
  
  // 同时删除可能存在的 unique_link 哈希键
  const targetUrl = await LINKS.get(shortCode)
  if (targetUrl) {
    // 如果是 unique_link 模式，可能有关联的哈希键
    // 这里简化处理，只删除短码本身
    await LINKS.delete(shortCode)
  }
  
  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  })
}
