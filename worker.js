/**
 * CloudPress v20.1 — Originless Edge CMS Worker ()
 *
 *  :
 *  - CP.apiFetch is not a function   
 *  -    KV   (  → KV lookup)
 *  -  wp-admin  → wp-login.php  (  )
 *  -   fetch    fetch()  (CP.apiFetch )
 *  -     (POST → D1 user  → KV   →  Set)
 *  -     (wordpress_logged_in_SESSION)
 *  - bcrypt/MD5    plain password fallback 
 */

//   
const CACHE_TTL_HTML   = 300;
const CACHE_TTL_ASSET  = 86400;
const CACHE_TTL_API    = 60;
const CACHE_TTL_STALE  = 86400;
const KV_PAGE_PREFIX   = 'page:';
const KV_SITE_PREFIX   = 'site_domain:';
const KV_OPT_PREFIX    = 'opt:';
const SESSION_COOKIE   = 'wordpress_logged_in_SESSION';
const SESSION_KV_PREFIX= 'wp_session:';
const RATE_LIMIT_WIN   = 60;
const RATE_LIMIT_MAX   = 300;
const RATE_LIMIT_MAX_W = 30;
const DDOS_BAN_TTL     = 3600;
const BOT_TARPIT_MS    = 5000;

//  WAF  
const WAF_SQLI = /('\s*(or|and)\s+'|--)|(union\s+select)|(;\s*(drop|delete|insert|update)\s)/i;
const WAF_XSS  = /(<\s*script|javascript:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed|<\s*svg.*on\w+=|data:\s*text\/html)/i;
const WAF_PATH = /(\.\.(\/|\\)|\/etc\/passwd|\/proc\/self|cmd\.exe|powershell|\/bin\/sh|\/bin\/bash)/i;
const WAF_RFI  = /(https?:\/\/(?!(?:[\w-]+\.)?(?:cloudflare|cloudpress|wordpress)\.(?:com|net|org|site|dev))[\w.-]+\/.*\.(php|asp|aspx|jsp|cgi))/i;

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function cacheKey(request) {
  const url = new URL(request.url);
  const skipParams = new Set(['utm_source','utm_medium','utm_campaign','utm_content','utm_term','fbclid','gclid','_ga']);
  const params = [...url.searchParams.entries()]
    .filter(([k]) => !skipParams.has(k))
    .sort(([a],[b]) => a.localeCompare(b));
  const cleanSearch = params.length ? '?' + new URLSearchParams(params).toString() : '';
  return `${url.origin}${url.pathname}${cleanSearch}`;
}

function wafCheck(request, url) {
  const path = decodeURIComponent(url.pathname);
  const query = decodeURIComponent(url.search);
  const ua = request.headers.get('user-agent') || '';
  if (WAF_PATH.test(path)) return { block: true, reason: 'path_traversal', status: 403 };
  if (WAF_SQLI.test(path) || WAF_SQLI.test(query)) return { block: true, reason: 'sqli', status: 403 };
  if (WAF_XSS.test(path) || WAF_XSS.test(query)) return { block: true, reason: 'xss', status: 403 };
  if (WAF_RFI.test(query)) return { block: true, reason: 'rfi', status: 403 };
  const badBot = /sqlmap|nikto|nessus|masscan|zgrab|dirbuster|nuclei|openvas|acunetix|havij|pangolin/i;
  if (badBot.test(ua)) return { block: true, reason: 'bad_bot', status: 403, tarpit: true };
  if (path === '/xmlrpc.php') return { block: true, reason: 'xmlrpc', status: 403 };
  return { block: false };
}

async function rateLimitCheck(env, ip, isWrite, pathname) {
  if (!env.CACHE) return { allowed: true };
  const isLoginPath = pathname === '/wp-login.php' || pathname === '/wp-admin/';
  const maxReq = isLoginPath ? 10 : (isWrite ? RATE_LIMIT_MAX_W : RATE_LIMIT_MAX);
  const banKey   = `ddos_ban:${ip}`;
  const countKey = `rl:${ip}:${Math.floor(Date.now() / 1000 / RATE_LIMIT_WIN)}`;
  try {
    const banned = await env.CACHE.get(banKey);
    if (banned) return { allowed: false, banned: true };
    const cur = parseInt(await env.CACHE.get(countKey) || '0', 10);
    if (cur >= maxReq) {
      if (cur >= maxReq * 3) {
        await env.CACHE.put(banKey, '1', { expirationTtl: DDOS_BAN_TTL });
      }
      return { allowed: false, limit: maxReq, current: cur };
    }
    env.CACHE.put(countKey, String(cur + 1), { expirationTtl: RATE_LIMIT_WIN + 5 }).catch(() => {});
    return { allowed: true };
  } catch {
    return { allowed: true };
  }
}

function getClientIP(request) {
  return request.headers.get('cf-connecting-ip')
    || request.headers.get('x-real-ip')
    || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || '0.0.0.0';
}

function isStaticAsset(pathname) {
  return /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|webp|avif|mp4|webm|pdf|zip|gz|xml|txt|json)$/i.test(pathname);
}

function isCacheable(request, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return false;
  const p = url.pathname;
  if (p.startsWith('/wp-admin') || p.startsWith('/wp-login')) return false;
  if (url.searchParams.has('nocache') || url.searchParams.has('preview')) return false;
  const cookie = request.headers.get('cookie') || '';
  if (/wordpress_logged_in|wp-postpass/i.test(cookie)) return false;
  return true;
}

const edgeCache = caches.default;

async function cacheGet(request) {
  try {
    const cached = await edgeCache.match(request);
    if (!cached) return null;
    const age = parseInt(cached.headers.get('x-cp-age') || '0', 10);
    const ttl = parseInt(cached.headers.get('x-cp-ttl') || String(CACHE_TTL_HTML), 10);
    const stale = Date.now() / 1000 - age > ttl;
    return { response: cached, stale };
  } catch { return null; }
}

async function cachePut(ctx, request, response, ttl = CACHE_TTL_HTML) {
  if (!response.ok && response.status !== 301 && response.status !== 302) return;
  try {
    const cloned = response.clone();
    const headers = new Headers(cloned.headers);
    headers.set('Cache-Control', `public, max-age=${ttl}, stale-while-revalidate=${CACHE_TTL_STALE}`);
    headers.set('x-cp-age', String(Math.floor(Date.now() / 1000)));
    headers.set('x-cp-ttl', String(ttl));
    headers.set('x-cp-cached', 'edge');
    const cachedResp = new Response(cloned.body, { status: cloned.status, headers });
    ctx.waitUntil(edgeCache.put(request, cachedResp));
  } catch {}
}

async function kvCacheGet(env, key) {
  if (!env.CACHE) return null;
  try {
    const meta = await env.CACHE.getWithMetadata(KV_PAGE_PREFIX + key, { type: 'text' });
    if (!meta || !meta.value) return null;
    const { contentType, status, cachedAt, ttl } = meta.metadata || {};
    const stale = Date.now() / 1000 - (cachedAt || 0) > (ttl || CACHE_TTL_HTML);
    return { body: meta.value, contentType, status: status || 200, stale, cachedAt };
  } catch { return null; }
}

async function kvCachePut(env, key, body, contentType = 'text/html; charset=utf-8', status = 200, ttl = CACHE_TTL_HTML) {
  if (!env.CACHE) return;
  try {
    await env.CACHE.put(
      KV_PAGE_PREFIX + key,
      body,
      { expirationTtl: CACHE_TTL_STALE, metadata: { contentType, status, cachedAt: Math.floor(Date.now() / 1000), ttl } }
    );
  } catch {}
}

//    (KV  ) 
function getSessionToken(request) {
  const cookie = request.headers.get('cookie') || '';
  // wordpress_logged_in_SESSION=<token> 
  const match = cookie.match(/wordpress_logged_in_[^=]+=([^;]+)/);
  return match ? match[1].trim() : null;
}

async function validateSession(env, request) {
  const token = getSessionToken(request);
  if (!token) return null;
  if (!env.CACHE) return null;
  try {
    const raw = await env.CACHE.get(SESSION_KV_PREFIX + token);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch { return null; }
}

//  KV    
async function getSiteInfo(env, hostname) {
  if (env.CACHE) {
    try {
      const cached = await env.CACHE.get(KV_SITE_PREFIX + hostname, { type: 'json' });
      if (cached) return cached;
    } catch {}
  }
  if (env.DB) {
    try {
      const row = await env.DB.prepare(
        `SELECT id, name, site_prefix, status, suspended,
                supabase_url, supabase_key, supabase_url2, supabase_key2,
                site_d1_id, site_kv_id, storage_bucket, storage_bucket2
           FROM sites
          WHERE (primary_domain = ? OR custom_domain = ?)
            AND domain_status = 'active'
            AND deleted_at IS NULL
          LIMIT 1`
      ).bind(hostname, hostname).first();
      if (row) {
        const info = {
          id: row.id, name: row.name,
          site_prefix: row.site_prefix || row.id,
          status: row.status, suspended: row.suspended,
          supabase_url: row.supabase_url, supabase_key: row.supabase_key,
          supabase_url2: row.supabase_url2, supabase_key2: row.supabase_key2,
          site_d1_id: row.site_d1_id, site_kv_id: row.site_kv_id,
          storage_bucket: row.storage_bucket, storage_bucket2: row.storage_bucket2,
        };
        if (env.CACHE) {
          env.CACHE.put(KV_SITE_PREFIX + hostname, JSON.stringify(info), { expirationTtl: 86400 }).catch(() => {});
        }
        return info;
      }
    } catch (e) {
      console.warn('[worker] D1 site lookup error:', e?.message);
    }
  }
  return null;
}

async function getWPOptions(env, sitePrefix, keys) {
  const result = {};
  const missing = [];
  for (const k of keys) {
    const kvKey = `${KV_OPT_PREFIX}${sitePrefix}:${k}`;
    try {
      const v = env.CACHE ? await env.CACHE.get(kvKey) : null;
      if (v !== null) result[k] = v;
      else missing.push(k);
    } catch { missing.push(k); }
  }
  if (missing.length && env.DB) {
    try {
      const placeholders = missing.map(() => '?').join(',');
      const rows = await env.DB.prepare(
        `SELECT option_name, option_value FROM wp_options WHERE option_name IN (${placeholders}) LIMIT 50`
      ).bind(...missing).all();
      for (const row of (rows.results || [])) {
        result[row.option_name] = row.option_value;
        if (env.CACHE) {
          env.CACHE.put(`${KV_OPT_PREFIX}${sitePrefix}:${row.option_name}`, row.option_value, { expirationTtl: 3600 }).catch(() => {});
        }
      }
    } catch {}
  }
  return result;
}

async function supabaseUpload(siteInfo, bucket, path, body, contentType) {
  if (siteInfo.supabase_url && siteInfo.supabase_key) {
    try {
      const res = await fetch(`${siteInfo.supabase_url}/storage/v1/object/${bucket}/${path}`, {
        method: 'POST',
        headers: {
          'apikey': siteInfo.supabase_key,
          'Authorization': `Bearer ${siteInfo.supabase_key}`,
          'Content-Type': contentType,
        },
        body,
      });
      if (res.ok || res.status === 200 || res.status === 201) {
        return { ok: true, url: `${siteInfo.supabase_url}/storage/v1/object/public/${bucket}/${path}` };
      }
      if (res.status === 413 || res.status === 402) throw new Error('quota_exceeded');
    } catch (e) { if (e.message !== 'quota_exceeded') {} }
  }
  if (siteInfo.supabase_url2 && siteInfo.supabase_key2) {
    try {
      const bucket2 = siteInfo.storage_bucket2 || bucket;
      const res = await fetch(`${siteInfo.supabase_url2}/storage/v1/object/${bucket2}/${path}`, {
        method: 'POST',
        headers: {
          'apikey': siteInfo.supabase_key2,
          'Authorization': `Bearer ${siteInfo.supabase_key2}`,
          'Content-Type': contentType,
        },
        body,
      });
      if (res.ok) {
        return { ok: true, url: `${siteInfo.supabase_url2}/storage/v1/object/public/${bucket2}/${path}`, secondary: true };
      }
    } catch {}
  }
  return { ok: false, error: 'all_storage_failed' };
}

//  Edge SSR 
async function renderWordPressPage(env, siteInfo, url, request) {
  const sitePrefix = siteInfo.site_prefix;
  const hostname = url.hostname;
  const pathname = url.pathname;
  const search = url.search;

  const opts = await getWPOptions(env, sitePrefix, [
    'blogname', 'blogdescription', 'siteurl', 'home',
    'template', 'stylesheet', 'active_plugins', 'permalink_structure',
    'posts_per_page', 'date_format', 'time_format', 'timezone_string',
    'admin_email', 'default_comment_status',
  ]);

  const siteName = opts.blogname || siteInfo.name || hostname;
  const siteDesc = opts.blogdescription || '';
  const siteUrl  = `https://${hostname}`;
  const themeDir = opts.stylesheet || opts.template || 'twentytwentyfour';

  const contentData = await resolveWPRoute(env, sitePrefix, pathname, search, opts);

  const html = await renderWPTemplate(env, sitePrefix, siteInfo, contentData, {
    siteName, siteDesc, siteUrl, themeDir, opts, hostname, pathname,
  });

  return { html, contentData };
}

async function resolveWPRoute(env, sitePrefix, pathname, search, opts) {
  const searchParams = new URLSearchParams(search);
  const p = searchParams.get('p');
  const catSlug  = searchParams.get('cat') || searchParams.get('category_name');
  const tagSlug  = searchParams.get('tag');
  const postSlug = pathname.replace(/^\/|\/$/g,'');

  let type = 'home', posts = [], post = null, term = null;

  if (!env.DB) return { type: 'home', post: null, posts: [], term: null };
  try {
    if (pathname === '/' || pathname === '') {
      const frontPage = opts.page_on_front ? parseInt(opts.page_on_front, 10) : 0;
      if (frontPage) {
        post = await env.DB.prepare(
          `SELECT * FROM wp_posts WHERE ID = ? AND post_status = 'publish' LIMIT 1`
        ).bind(frontPage).first();
        type = 'page';
      } else {
        const perPage = parseInt(opts.posts_per_page || '10', 10);
        const res = await env.DB.prepare(
          `SELECT ID, post_title, post_content, post_excerpt, post_date, post_name, post_author, comment_count
             FROM wp_posts
            WHERE post_type = 'post' AND post_status = 'publish'
            ORDER BY post_date DESC LIMIT ?`
        ).bind(perPage).all();
        posts = res.results || [];
        type = 'home';
      }
    } else if (p) {
      post = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE ID = ? AND post_status = 'publish' LIMIT 1`
      ).bind(parseInt(p, 10)).first();
      type = post?.post_type === 'page' ? 'page' : 'single';
    } else if (catSlug) {
      const cat = await env.DB.prepare(
        `SELECT t.*, tt.description, tt.count, tt.term_taxonomy_id
           FROM wp_terms t
           JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
          WHERE t.slug = ? AND tt.taxonomy = 'category' LIMIT 1`
      ).bind(catSlug).first();
      if (cat) {
        term = cat;
        const res = await env.DB.prepare(
          `SELECT p.ID, p.post_title, p.post_content, p.post_excerpt, p.post_date, p.post_name
             FROM wp_posts p
             JOIN wp_term_relationships tr ON tr.object_id = p.ID
            WHERE tr.term_taxonomy_id = ? AND p.post_status = 'publish' AND p.post_type = 'post'
            ORDER BY p.post_date DESC LIMIT 10`
        ).bind(cat.term_taxonomy_id).all();
        posts = res.results || [];
        type = 'archive';
      } else { type = '404'; }
    } else if (tagSlug) {
      const tag = await env.DB.prepare(
        `SELECT t.*, tt.description, tt.term_taxonomy_id
           FROM wp_terms t
           JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
          WHERE t.slug = ? AND tt.taxonomy = 'post_tag' LIMIT 1`
      ).bind(tagSlug).first();
      if (tag) {
        term = tag;
        const res = await env.DB.prepare(
          `SELECT p.ID, p.post_title, p.post_content, p.post_excerpt, p.post_date, p.post_name
             FROM wp_posts p
             JOIN wp_term_relationships tr ON tr.object_id = p.ID
            WHERE tr.term_taxonomy_id = ? AND p.post_status = 'publish' AND p.post_type = 'post'
            ORDER BY p.post_date DESC LIMIT 10`
        ).bind(tag.term_taxonomy_id).all();
        posts = res.results || [];
        type = 'archive';
      } else { type = '404'; }
    } else if (postSlug) {
      post = await env.DB.prepare(
        `SELECT * FROM wp_posts
          WHERE post_name = ? AND post_status = 'publish'
            AND post_type IN ('post', 'page')
          LIMIT 1`
      ).bind(postSlug).first();
      if (post) {
        type = post.post_type === 'page' ? 'page' : 'single';
        if (post.ID) {
          const metaRes = await env.DB.prepare(
            `SELECT meta_key, meta_value FROM wp_postmeta WHERE post_id = ? LIMIT 50`
          ).bind(post.ID).all();
          post._meta = {};
          for (const m of (metaRes.results || [])) {
            post._meta[m.meta_key] = m.meta_value;
          }
          const taxRes = await env.DB.prepare(
            `SELECT t.name, t.slug, tt.taxonomy
               FROM wp_terms t
               JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id
               JOIN wp_term_relationships tr ON tr.term_taxonomy_id = tt.term_taxonomy_id
              WHERE tr.object_id = ? AND tt.taxonomy IN ('category','post_tag')`
          ).bind(post.ID).all();
          post._categories = (taxRes.results || []).filter(r => r.taxonomy === 'category');
          post._tags       = (taxRes.results || []).filter(r => r.taxonomy === 'post_tag');
        }
      } else { type = '404'; }
    }
  } catch (e) {
    console.warn('[SSR] DB query error:', e.message);
    type = 'home';
    posts = [];
  }

  return { type, post, posts, term };
}

async function renderWPTemplate(env, sitePrefix, siteInfo, contentData, ctx) {
  const { siteName, siteDesc, siteUrl, opts, hostname, pathname } = ctx;
  const { type, post, posts, term } = contentData;

  let recentPosts = [];
  if (env.DB) {
    try {
      const rp = await env.DB.prepare(
        `SELECT ID, post_title, post_name, post_date FROM wp_posts
          WHERE post_type = 'post' AND post_status = 'publish'
          ORDER BY post_date DESC LIMIT 5`
      ).all();
      recentPosts = rp.results || [];
    } catch {}
  }

  let navItems = [];
  if (env.DB) {
    try {
      const navRes = await env.DB.prepare(
        `SELECT p.post_title, pm.meta_value as url, p.menu_order
           FROM wp_posts p
           LEFT JOIN wp_postmeta pm ON pm.post_id = p.ID AND pm.meta_key = '_menu_item_url'
          WHERE p.post_type = 'nav_menu_item' AND p.post_status = 'publish'
          ORDER BY p.menu_order ASC LIMIT 20`
      ).all();
      navItems = navRes.results || [];
    } catch {}
  }

  let mainContent = '';
  let pageTitle   = siteName;
  let metaDesc    = siteDesc;

  if (type === 'single' || type === 'page') {
    pageTitle = esc(post?.post_title || siteName);
    metaDesc  = esc(post?.post_excerpt || siteDesc);
    const cats = (post?._categories || []).map(c =>
      `<a href="${esc(siteUrl)}/?category_name=${esc(c.slug)}" rel="category tag">${esc(c.name)}</a>`
    ).join(', ');
    const tags = (post?._tags || []).map(t =>
      `<a href="${esc(siteUrl)}/?tag=${esc(t.slug)}" rel="tag">${esc(t.name)}</a>`
    ).join(', ');

    mainContent = `
<article id="post-${post?.ID || 0}" class="post-${post?.ID || 0} ${post?.post_type || 'post'} type-${post?.post_type || 'post'} status-publish hentry">
  <header class="entry-header">
    <h1 class="entry-title">${esc(post?.post_title || '')}</h1>
    ${type === 'single' ? `<div class="entry-meta">
      <time class="entry-date published" datetime="${esc(post?.post_date || '')}">${formatDate(post?.post_date, opts.date_format)}</time>
      ${cats ? `<span class="cat-links">${cats}</span>` : ''}
    </div>` : ''}
  </header>
  <div class="entry-content">${renderShortcodes(post?.post_content || '')}</div>
  ${tags ? `<footer class="entry-footer"><span class="tags-links">${tags}</span></footer>` : ''}
</article>`;
  } else if (type === 'home' || type === 'archive') {
    if (type === 'archive' && term) {
      pageTitle = esc(term.name);
      metaDesc  = esc(term.description || '');
      mainContent += `<header class="page-header"><h1 class="page-title">${esc(term.name)}</h1>${term.description ? `<div class="taxonomy-description">${esc(term.description)}</div>` : ''}</header>`;
    }
    if (posts.length === 0) {
      // 빈 사이트 - 워드프레스와 동일하게 샘플 콘텐츠 표시
      mainContent += `
<article id="post-1" class="post-1 post type-post status-publish hentry">
  <header class="entry-header">
    <h2 class="entry-title"><a href="${esc(siteUrl)}/" rel="bookmark">Hello world!</a></h2>
    <div class="entry-meta"><time class="entry-date published">날짜</time></div>
  </header>
  <div class="entry-summary">
    <p>WordPress에 오신 것을 환영합니다. 이것은 첫 번째 게시물입니다. 이 게시물을 편집하거나 삭제하고 블로그를 시작하세요!</p>
    <a href="${esc(siteUrl)}/wp-admin/edit.php" class="more-link">게시물 관리</a>
  </div>
</article>`;
    } else {
      mainContent += '<div class="posts-loop">';
      for (const p of posts) {
        const excerpt = (p.post_excerpt || p.post_content || '').slice(0, 300).replace(/<[^>]+>/g, '');
        mainContent += `
<article id="post-${p.ID}" class="post-${p.ID} post type-post status-publish hentry">
  <header class="entry-header">
    <h2 class="entry-title"><a href="${esc(siteUrl)}/${esc(p.post_name)}/" rel="bookmark">${esc(p.post_title)}</a></h2>
    <div class="entry-meta"><time class="entry-date published" datetime="${esc(p.post_date)}">${formatDate(p.post_date, opts.date_format)}</time></div>
  </header>
  <div class="entry-summary"><p>${esc(excerpt.slice(0, 200))}${excerpt.length > 200 ? '…' : ''}</p><a href="${esc(siteUrl)}/${esc(p.post_name)}/" class="more-link"> </a></div>
</article>`;
      }
      mainContent += '</div>';
    }
  } else if (type === '404') {
    pageTitle = '페이지를 찾을 수 없습니다';
    mainContent = `<div class="error-404 not-found"><h1>404</h1><p>요청하신 페이지를 찾을 수 없습니다.</p><a href="${esc(siteUrl)}/">홈으로 돌아가기</a></div>`;
  } else if (type === 'error') {
    pageTitle = siteName;
    mainContent = `<div style="text-align:center;padding:3rem 1rem;color:#767676"><p>일시적인 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.</p></div>`;
  }
  const navHtml = navItems.length
    ? navItems.map(n => `<li class="menu-item"><a href="${esc(n.url || siteUrl + '/')}">${esc(n.post_title)}</a></li>`).join('')
    : `<li class="menu-item"><a href="${esc(siteUrl)}/"></a></li>`;

  const sidebarHtml = `
<aside id="secondary" class="widget-area">
  <section id="recent-posts" class="widget widget_recent_entries">
    <h2 class="widget-title"> </h2>
    <ul>${recentPosts.length ? recentPosts.map(rp => `<li><a href="${esc(siteUrl)}/${esc(rp.post_name)}/">${esc(rp.post_title)}</a></li>`).join('') : '<li> .</li>'}</ul>
  </section>
</aside>`;

  return `<!DOCTYPE html>
<html lang="ko" class="no-js">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="WordPress 6.7">
  <meta name="color-scheme" content="light">
  <title>${pageTitle}${type !== 'home' ? ` – ${esc(siteName)}` : ''}</title>
  <meta name="description" content="${metaDesc}">
  <link rel="canonical" href="${esc(siteUrl + pathname)}">
  <link rel="alternate" type="application/rss+xml" title="${esc(siteName)} &raquo; " href="${esc(siteUrl)}/feed/">
  <style>
    :root{--wp--preset--color--black:#000;--wp--preset--color--white:#fff;--wp--preset--font-size--small:13px;--wp--preset--font-size--medium:20px;--wp--preset--font-size--large:36px;}
    *,::after,::before{box-sizing:border-box}
    html{font-size:16px;scroll-behavior:smooth;color-scheme:light;background:#fff}
    body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:1rem;line-height:1.7;color:#1e1e1e;background:#fff;color-scheme:light}
    a{color:#0073aa;text-decoration:none}a:hover{text-decoration:underline;color:#005580}
    img{max-width:100%;height:auto}
    .site{display:flex;flex-direction:column;min-height:100vh}
    .site-header{background:#fff;border-bottom:1px solid #e0e0e0;padding:.8rem 0;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.1)}
    .header-inner{max-width:1200px;margin:0 auto;padding:0 1.5rem;display:flex;align-items:center;justify-content:space-between;gap:1rem}
    .site-branding .site-title{margin:0;font-size:1.5rem;font-weight:700}.site-branding .site-title a{color:#1e1e1e}
    .site-branding .site-description{margin:.25rem 0 0;color:#767676;font-size:.875rem}
    nav.main-navigation ul{list-style:none;margin:0;padding:0;display:flex;gap:1.5rem;flex-wrap:wrap}
    nav.main-navigation ul li a{font-size:.9375rem;color:#1e1e1e;font-weight:500;padding:.25rem 0;border-bottom:2px solid transparent;transition:border-color .2s}
    nav.main-navigation ul li a:hover{border-bottom-color:#0073aa;text-decoration:none}
    .site-content{flex:1;max-width:1200px;margin:0 auto;padding:2rem 1.5rem;width:100%;display:grid;grid-template-columns:1fr 300px;gap:2.5rem}
    @media(max-width:768px){.site-content{grid-template-columns:1fr}}
    .entry-header{margin-bottom:1.5rem}
    .entry-title{font-size:1.75rem;font-weight:700;margin:0 0 .5rem;line-height:1.3}
    .entry-title a{color:#1e1e1e}.entry-title a:hover{color:#0073aa;text-decoration:none}
    .entry-meta{color:#767676;font-size:.875rem;margin-bottom:.5rem}
    .entry-content{line-height:1.8;font-size:1rem}
    .entry-content p{margin:0 0 1.25rem}
    .entry-summary{margin-bottom:.75rem}.entry-summary p{margin:0}
    .more-link{display:inline-block;margin-top:.5rem;padding:.35rem .875rem;background:#0073aa;color:#fff;border-radius:3px;font-size:.875rem;font-weight:500;transition:background .15s}
    .more-link:hover{background:#005580;color:#fff;text-decoration:none}
    .posts-loop article{padding:1.5rem 0;border-bottom:1px solid #e8e8e8}.posts-loop article:last-child{border-bottom:none}
    .error-404{text-align:center;padding:3rem 1rem}.error-404 h1{font-size:6rem;font-weight:900;color:#0073aa;margin:0}
    .widget-area{font-size:.9375rem}
    .widget{margin-bottom:2rem;padding:1.5rem;background:#f9f9f9;border-radius:6px;border:1px solid #e8e8e8}
    .widget-title{font-size:1rem;font-weight:700;margin:0 0 1rem;padding-bottom:.5rem;border-bottom:2px solid #0073aa}
    .widget ul{list-style:none;margin:0;padding:0}
    .widget ul li{padding:.4rem 0;border-bottom:1px solid #eee}.widget ul li:last-child{border-bottom:none}
    .site-footer{background:#1e1e1e;color:#a0a0a0;padding:2rem 1.5rem;text-align:center;font-size:.875rem;margin-top:auto}
    .site-footer a{color:#c0c0c0}.site-footer a:hover{color:#fff}
    .no-posts{text-align:center;padding:3rem 1rem;color:#767676}
    .no-posts .page-title{font-size:1.5rem;color:#1e1e1e;margin-bottom:1rem}
    .btn-admin,.btn-login{display:inline-block;margin:.5rem .25rem;padding:.5rem 1.25rem;border-radius:4px;font-size:.9rem;font-weight:600}
    .btn-admin{background:#0073aa;color:#fff}.btn-admin:hover{background:#005580;text-decoration:none;color:#fff}
    .btn-login{background:#f0f0f0;color:#1e1e1e;border:1px solid #ccc}.btn-login:hover{background:#e0e0e0;text-decoration:none}
    .page-header{margin-bottom:2rem;padding-bottom:1rem;border-bottom:2px solid #0073aa}
    .page-title{font-size:1.5rem;font-weight:700;margin:0}
    .entry-footer{margin-top:1.5rem;padding-top:1rem;border-top:1px solid #e8e8e8;font-size:.875rem;color:#767676}
  </style>
</head>
<body class="wp-site-blocks ${type === 'single' ? 'single-post' : type === 'page' ? 'page' : type === 'home' ? 'home blog' : type}">
<div id="page" class="site">
  <header id="masthead" class="site-header">
    <div class="header-inner">
      <div class="site-branding">
        <p class="site-title"><a href="${esc(siteUrl)}/" rel="home">${esc(siteName)}</a></p>
        ${siteDesc ? `<p class="site-description">${esc(siteDesc)}</p>` : ''}
      </div>
      <nav id="site-navigation" class="main-navigation" aria-label=" ">
        <ul>${navHtml}</ul>
      </nav>
    </div>
  </header>

  <div id="content" class="site-content">
    <main id="primary" class="site-main">${mainContent}</main>
    ${sidebarHtml}
  </div>

  <footer id="colophon" class="site-footer">
    <div class="site-info">
      <a href="${esc(siteUrl)}/">${esc(siteName)}</a> &mdash;
      <a href="https://wordpress.org/" target="_blank" rel="noopener">WordPress</a> 
      &nbsp;|&nbsp; Powered by <a href="https://cloudpress.site/" target="_blank" rel="noopener">CloudPress</a>
    </div>
  </footer>
</div>
<script>document.documentElement.className=document.documentElement.className.replace('no-js','js');</script>
</body>
</html>`;
}

function formatDate(dateStr, fmt) {
  if (!dateStr) return '';
  try {
    const d = new Date(dateStr);
    const year = d.getFullYear(), month = d.getMonth()+1, day = d.getDate();
    if (!fmt || fmt === 'Y n j') return `${year} ${month} ${day}`;
    return d.toLocaleDateString('ko-KR');
  } catch { return dateStr; }
}

function renderShortcodes(content) {
  if (!content) return '';
  return content
    .replace(/\[caption[^\]]*\](.*?)\[\/caption\]/gs, (_, inner) => `<figure class="wp-caption">${inner}</figure>`)
    .replace(/\[gallery[^\]]*\]/g, '<div class="gallery">[]</div>')
    .replace(/\[embed\](.*?)\[\/embed\]/g, (_, url) => `<div class="wp-embed-responsive"><a href="${esc(url)}" target="_blank" rel="noopener">${esc(url)}</a></div>`)
    .replace(/\[[\w_-]+[^\]]*\]/g, '')
    .replace(/\n\n+/g, '</p><p>')
    .replace(/^(?!<[a-z])/gm, (m) => m ? `<p>${m}` : m);
}

//  WordPress   
async function handleWPLogin(env, request, url, siteInfo) {
  const action = url.searchParams.get('action') || 'login';

  // 
  if (action === 'logout') {
    const token = getSessionToken(request);
    if (token && env.CACHE) {
      env.CACHE.delete(SESSION_KV_PREFIX + token).catch(() => {});
    }
    return new Response('', {
      status: 302,
      headers: {
        'Location': `https://${url.hostname}/wp-login.php`,
        'Set-Cookie': `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      },
    });
  }

  //    wp-admin
  const existing = await validateSession(env, request);
  if (existing) {
    const redirectTo = url.searchParams.get('redirect_to') || '/wp-admin/';
    return Response.redirect(`https://${url.hostname}${redirectTo}`, 302);
  }

  if (request.method === 'POST') {
    const body = await request.formData().catch(() => new FormData());
    const username = (body.get('log') || '').trim();
    const password = body.get('pwd') || '';
    const redirectTo = body.get('redirect_to') || '/wp-admin/';
    const rememberMe = body.get('rememberme') === 'forever';

    if (username && password) {
      try {
        const user = await env.DB.prepare(
          `SELECT ID, user_login, user_pass, user_email, display_name FROM wp_users WHERE user_login = ? OR user_email = ? LIMIT 1`
        ).bind(username, username).first();

        if (user && await verifyWPPassword(password, user.user_pass)) {
          const sessionToken = crypto.randomUUID();
          const ttl = rememberMe ? 30 * 24 * 3600 : 24 * 3600;
          const expiry = new Date(Date.now() + ttl * 1000).toUTCString();

          if (env.CACHE) {
            await env.CACHE.put(
              SESSION_KV_PREFIX + sessionToken,
              JSON.stringify({ userId: user.ID, login: user.user_login, displayName: user.display_name }),
              { expirationTtl: ttl }
            );
          }

          return new Response('', {
            status: 302,
            headers: {
              'Location': redirectTo,
              'Set-Cookie': `${SESSION_COOKIE}=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=${expiry}`,
            },
          });
        }
      } catch (e) {
        console.warn('[login] error:', e.message);
      }

      //  
      return new Response(renderLoginPage(siteInfo, '    .', url, username), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
      });
    }

    return new Response(renderLoginPage(siteInfo, '  .', url, ''), {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }

  return new Response(renderLoginPage(siteInfo, '', url, ''), {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function renderLoginPage(siteInfo, error, url, prefillUser = '') {
  const siteUrl  = url ? `https://${url.hostname}` : '';
  const siteName = esc(siteInfo?.name || 'WordPress');
  const redirectTo = url ? (url.searchParams.get('redirect_to') || '/wp-admin/') : '/wp-admin/';

  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title> – ${siteName}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    html,body{min-height:100%;background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    body{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:1rem}
    #login-logo{margin-bottom:1.5rem;text-align:center}
    #login-logo a{display:inline-block;text-decoration:none}
    #login-logo svg{width:84px;height:84px;fill:#1d2327}
    #login-logo .site-name{display:block;margin-top:.5rem;font-size:1rem;font-weight:700;color:#1d2327}
    #loginform-wrap{width:100%;max-width:360px}
    #loginform{background:#fff;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.13);padding:2rem 1.75rem}
    .login-error{background:#fff0f0;border-left:4px solid #d63638;padding:.75rem 1rem;margin-bottom:1.25rem;font-size:.875rem;color:#d63638;border-radius:0 4px 4px 0}
    .login-success{background:#f0fff4;border-left:4px solid #00a32a;padding:.75rem 1rem;margin-bottom:1.25rem;font-size:.875rem;color:#1a6630}
    label{display:block;font-size:.875rem;font-weight:600;margin-bottom:.375rem;color:#1d2327}
    .input-group{margin-bottom:1rem;position:relative}
    input[type=text],input[type=password]{width:100%;padding:.625rem .875rem;border:1px solid #8c8f94;border-radius:4px;font-size:1rem;line-height:1.5;transition:border-color .15s,box-shadow .15s;background:#fff;color:#1d2327}
    input[type=text]:focus,input[type=password]:focus{border-color:#2271b1;outline:0;box-shadow:0 0 0 2px rgba(34,113,177,.35)}
    .toggle-pw{position:absolute;right:.75rem;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#8c8f94;font-size:1rem;padding:0;line-height:1}
    .remember-row{display:flex;align-items:center;gap:.5rem;margin-bottom:1.25rem;font-size:.875rem;color:#1d2327}
    .remember-row input{width:16px;height:16px;cursor:pointer;accent-color:#2271b1}
    .btn-login{width:100%;padding:.6875rem 1rem;background:#2271b1;color:#fff;border:none;border-radius:4px;font-size:1rem;font-weight:600;cursor:pointer;transition:background .15s;letter-spacing:.01em}
    .btn-login:hover{background:#135e96}
    .btn-login:active{background:#0a4480}
    .login-footer{margin-top:1rem;text-align:center;font-size:.8125rem}
    .login-footer a{color:#2271b1}
    .login-footer a:hover{color:#135e96}
    .login-footer .sep{color:#c3c4c7;margin:0 .5rem}
    .back-link{display:block;text-align:center;margin-top:1.25rem;font-size:.8125rem;color:#646970}
    .back-link a{color:#2271b1}
  </style>
</head>
<body>
<div id="login-logo">
  <a href="${esc(siteUrl)}/">
    <svg viewBox="0 0 185 185" xmlns="http://www.w3.org/2000/svg"><path d="M92.5 6.5C45.2 6.5 6.5 45.2 6.5 92.5S45.2 178.5 92.5 178.5 178.5 139.8 178.5 92.5 139.8 6.5 92.5 6.5zm-64.3 86c0-35.5 28.8-64.3 64.3-64.3 14.1 0 27.1 4.6 37.6 12.3L44.5 130.1c-7.7-10.5-12.3-23.5-12.3-37.6zm64.3 64.3c-14.1 0-27.1-4.6-37.6-12.3l85.6-89.6c7.7 10.5 12.3 23.5 12.3 37.6 0 35.5-28.8 64.3-64.3 64.3z"/></svg>
    <span class="site-name">${siteName}</span>
  </a>
</div>

<div id="loginform-wrap">
  <form id="loginform" name="loginform" method="post" action="/wp-login.php">
    ${error ? `<div class="login-error">${esc(error)}</div>` : ''}
    <div class="input-group">
      <label for="user_login">   </label>
      <input type="text" name="log" id="user_login" value="${esc(prefillUser)}" autocomplete="username" autocapitalize="none" autocorrect="off" required>
    </div>
    <div class="input-group">
      <label for="user_pass"></label>
      <input type="password" name="pwd" id="user_pass" autocomplete="current-password" required>
      <button type="button" class="toggle-pw" onclick="togglePw()" aria-label="비밀번호 표시/숨기기">표시</button>
    </div>
    <div class="remember-row">
      <input type="checkbox" name="rememberme" id="rememberme" value="forever">
      <label for="rememberme" style="margin:0;font-weight:400">  </label>
    </div>
    <input type="hidden" name="redirect_to" value="${esc(redirectTo)}">
    <input type="hidden" name="testcookie" value="1">
    <button type="submit" name="wp-submit" id="wp-submit" class="btn-login"></button>
    <div class="login-footer">
      <a href="${esc(siteUrl)}/wp-login.php?action=lostpassword"> ?</a>
    </div>
  </form>
  <div class="back-link">
    <a href="${esc(siteUrl)}/">← ${siteName}() </a>
  </div>
</div>

<script>
function togglePw(){
  var el=document.getElementById('user_pass');
  el.type=el.type==='password'?'text':'password';
}
//  →  
document.getElementById('user_pass').addEventListener('keydown',function(e){
  if(e.key==='Enter'){e.preventDefault();document.getElementById('loginform').submit();}
});
</script>
</body>
</html>`;
}

//  WordPress   
async function verifyWPPassword(password, hash) {
  if (!hash) return false;
  // plain text (/ )
  if (!hash.startsWith('$')) return hash === password;
  // WordPress phpass ($P$)
  if (hash.startsWith('$P$')) return wpCheckPassword(password, hash);
  // bcrypt ($2y$, $2b$) — Workers  → plain  fallback
  if (hash.startsWith('$2y$') || hash.startsWith('$2b$')) return hash === password;
  // plain MD5 ()
  try {
    const enc = new TextEncoder().encode(password);
    const buf = await crypto.subtle.digest('SHA-256', enc); // MD5  → SHA-256
    const hex = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
    return hex === hash;
  } catch {}
  return false;
}

function wpCheckPassword(password, hash) {
  // phpass MD5 portable hash  ( JS, Workers )
  const itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  function md5(input) {
    //  MD5 (Workers crypto.subtle.digest('MD5')   JS  )
    function safeAdd(x, y) { const lsw=(x&0xffff)+(y&0xffff),msw=(x>>16)+(y>>16)+(lsw>>16);return(msw<<16)|(lsw&0xffff); }
    function bitRotateLeft(num,cnt){return(num<<cnt)|(num>>>(32-cnt));}
    function md5cmn(q,a,b,x,s,t){return safeAdd(bitRotateLeft(safeAdd(safeAdd(a,q),safeAdd(x,t)),s),b);}
    function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|(~b&d),a,b,x,s,t);}
    function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&~d),a,b,x,s,t);}
    function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
    function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|~d),a,b,x,s,t);}
    function unescape(s){const arr=[];for(let i=0;i<s.length;i++)arr.push(s.charCodeAt(i)&0xff);return arr;}
    const x=[];const str=unescape(input);const len8=str.length*8;
    for(let i=0;i<str.length;i+=4)x[i>>2]=(str[i])|(str[i+1]<<8)|(str[i+2]<<16)|(str[i+3]<<24);
    x[len8>>5]|=(0x80<<(len8%32));x[((len8+64>>>9)<<4)+14]=len8;
    let a=1732584193,b=-271733879,c=-1732584194,d=271733878;
    for(let i=0;i<x.length;i+=16){
      const oA=a,oB=b,oC=c,oD=d;
      a=md5ff(a,b,c,d,x[i],7,-680876936);d=md5ff(d,a,b,c,x[i+1],12,-389564586);c=md5ff(c,d,a,b,x[i+2],17,606105819);b=md5ff(b,c,d,a,x[i+3],22,-1044525330);
      a=md5ff(a,b,c,d,x[i+4],7,-176418897);d=md5ff(d,a,b,c,x[i+5],12,1200080426);c=md5ff(c,d,a,b,x[i+6],17,-1473231341);b=md5ff(b,c,d,a,x[i+7],22,-45705983);
      a=md5ff(a,b,c,d,x[i+8],7,1770035416);d=md5ff(d,a,b,c,x[i+9],12,-1958414417);c=md5ff(c,d,a,b,x[i+10],17,-42063);b=md5ff(b,c,d,a,x[i+11],22,-1990404162);
      a=md5ff(a,b,c,d,x[i+12],7,1804603682);d=md5ff(d,a,b,c,x[i+13],12,-40341101);c=md5ff(c,d,a,b,x[i+14],17,-1502002290);b=md5ff(b,c,d,a,x[i+15],22,1236535329);
      a=md5gg(a,b,c,d,x[i+1],5,-165796510);d=md5gg(d,a,b,c,x[i+6],9,-1069501632);c=md5gg(c,d,a,b,x[i+11],14,643717713);b=md5gg(b,c,d,a,x[i],20,-373897302);
      a=md5gg(a,b,c,d,x[i+5],5,-701558691);d=md5gg(d,a,b,c,x[i+10],9,38016083);c=md5gg(c,d,a,b,x[i+15],14,-660478335);b=md5gg(b,c,d,a,x[i+4],20,-405537848);
      a=md5gg(a,b,c,d,x[i+9],5,568446438);d=md5gg(d,a,b,c,x[i+14],9,-1019803690);c=md5gg(c,d,a,b,x[i+3],14,-187363961);b=md5gg(b,c,d,a,x[i+8],20,1163531501);
      a=md5gg(a,b,c,d,x[i+13],5,-1444681467);d=md5gg(d,a,b,c,x[i+2],9,-51403784);c=md5gg(c,d,a,b,x[i+7],14,1735328473);b=md5gg(b,c,d,a,x[i+12],20,-1926607734);
      a=md5hh(a,b,c,d,x[i+5],4,-378558);d=md5hh(d,a,b,c,x[i+8],11,-2022574463);c=md5hh(c,d,a,b,x[i+11],16,1839030562);b=md5hh(b,c,d,a,x[i+14],23,-35309556);
      a=md5hh(a,b,c,d,x[i+1],4,-1530992060);d=md5hh(d,a,b,c,x[i+4],11,1272893353);c=md5hh(c,d,a,b,x[i+7],16,-155497632);b=md5hh(b,c,d,a,x[i+10],23,-1094730640);
      a=md5hh(a,b,c,d,x[i+13],4,681279174);d=md5hh(d,a,b,c,x[i],11,-358537222);c=md5hh(c,d,a,b,x[i+3],16,-722521979);b=md5hh(b,c,d,a,x[i+6],23,76029189);
      a=md5hh(a,b,c,d,x[i+9],4,-640364487);d=md5hh(d,a,b,c,x[i+12],11,-421815835);c=md5hh(c,d,a,b,x[i+15],16,530742520);b=md5hh(b,c,d,a,x[i+2],23,-995338651);
      a=md5ii(a,b,c,d,x[i],6,-198630844);d=md5ii(d,a,b,c,x[i+7],10,1126891415);c=md5ii(c,d,a,b,x[i+14],15,-1416354905);b=md5ii(b,c,d,a,x[i+5],21,-57434055);
      a=md5ii(a,b,c,d,x[i+12],6,1700485571);d=md5ii(d,a,b,c,x[i+3],10,-1894986606);c=md5ii(c,d,a,b,x[i+10],15,-1051523);b=md5ii(b,c,d,a,x[i+1],21,-2054922799);
      a=md5ii(a,b,c,d,x[i+8],6,1873313359);d=md5ii(d,a,b,c,x[i+15],10,-30611744);c=md5ii(c,d,a,b,x[i+6],15,-1560198380);b=md5ii(b,c,d,a,x[i+13],21,1309151649);
      a=md5ii(a,b,c,d,x[i+4],6,-145523070);d=md5ii(d,a,b,c,x[i+11],10,-1120210379);c=md5ii(c,d,a,b,x[i+2],15,718787259);b=md5ii(b,c,d,a,x[i+9],21,-343485551);
      a=safeAdd(a,oA);b=safeAdd(b,oB);c=safeAdd(c,oC);d=safeAdd(d,oD);
    }
    return [a,b,c,d];
  }

  function md5Hex(s) {
    const words=md5(s);
    return words.map(w=>{const hex=((w&0xff)<<24|(w>>8&0xff)<<16|(w>>16&0xff)<<8|w>>>24)>>>0;return hex.toString(16).padStart(8,'0');}).join('');
  }

  if (hash.length !== 34) return false;
  const countLog2 = itoa64.indexOf(hash[3]);
  if (countLog2 < 7 || countLog2 > 30) return false;
  let count = 1 << countLog2;
  const salt = hash.substring(4, 12);
  let computed = md5Hex(salt + password);
  do { computed = md5Hex(computed + password); } while (--count);

  // encode64
  function encode64(input, count2) {
    const arr = [];
    for (let i = 0; i < 16; i++) arr.push(input.charCodeAt(i*2)|(input.charCodeAt(i*2+1)<<8) || (parseInt(input.slice(i*2,i*2+2),16)&0xff));
    // simplified: work with raw hex bytes
    const bytes = [];
    for (let i = 0; i < input.length; i+=2) bytes.push(parseInt(input.slice(i,i+2),16));
    let out = '', idx = 0;
    do {
      let value = bytes[idx++];
      out += itoa64[value & 63];
      if (idx < count2) value |= bytes[idx] << 8;
      out += itoa64[(value >> 6) & 63];
      if (idx++ >= count2) break;
      if (idx < count2) value |= bytes[idx] << 8;
      out += itoa64[(value >> 12) & 63];
      if (idx++ >= count2) break;
      out += itoa64[(value >> 18) & 63];
    } while (idx < count2);
    return out;
  }

  const output = '$P$' + hash[3] + salt + encode64(computed, 16);
  return output === hash;
}

function hashSimple(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  return Math.abs(h).toString(16).slice(0, 8);
}

//  wp-admin  
async function handleWPAdmin(env, request, url, siteInfo) {
  //  KV  
  const session = await validateSession(env, request);

  if (!session && url.pathname !== '/wp-login.php') {
    const loginUrl = `https://${url.hostname}/wp-login.php?redirect_to=${encodeURIComponent(url.pathname + url.search)}`;
    return Response.redirect(loginUrl, 302);
  }

  return new Response(renderAdminPage(url.pathname, siteInfo, url, session), {
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, private',
      'X-Frame-Options': 'SAMEORIGIN',
    },
  });
}

function renderAdminPage(pathname, siteInfo, urlObj, session) {
  const siteName = esc(siteInfo?.name || 'WordPress');
  const siteUrl  = urlObj ? `https://${urlObj.hostname}` : '';
  const page = pathname.replace(/^\/wp-admin\/?/, '').replace(/\.php$/, '') || 'index';
  const sp = urlObj ? urlObj.searchParams : null;
  const isPage = sp ? sp.get('post_type') === 'page' : false;
  const displayName = esc(session?.displayName || session?.login || 'admin');

  let pageTitle = '';
  let bodyHtml  = '';
  let inlineScript = '';

  if (page === 'index' || page === '' || page === 'dashboard') {
    pageTitle = '';
    bodyHtml = `
<div class="welcome-panel">
  <div style="max-width:700px">
    <h2 style="font-size:1.3rem;margin:0 0 10px">WordPress   !</h2>
    <p style="color:#50575e;margin:0 0 6px">CloudPress Edge  WordPress  .</p>
    <p style="color:#50575e;margin:0 0 15px;font-size:.85rem">: <strong>${displayName}</strong></p>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a href="/wp-admin/post-new.php" class="btn-wp"> </a>
      <a href="/wp-admin/edit.php" class="btn-wp btn-secondary"> </a>
      <a href="/wp-admin/options-general.php" class="btn-wp btn-secondary"> </a>
      <a href="/" target="_blank" class="btn-wp btn-secondary"> </a>
    </div>
  </div>
</div>
<div class="admin-widgets">
  <div class="admin-widget">
    <h3 class="widget-title"><span>  </span></h3>
    <div class="widget-body">
      <ul id="admin-glance" style="list-style:none;margin:0;padding:0;color:#50575e;font-size:.875rem"><li> ...</li></ul>
      <p style="margin:12px 0 0;font-size:.8rem;color:#50575e">WordPress 6.7 + CloudPress v20.1</p>
    </div>
  </div>
  <div class="admin-widget">
    <h3 class="widget-title"> </h3>
    <div class="widget-body">
      <div id="admin-activity" style="color:#50575e;font-size:.85rem"> ...</div>
    </div>
  </div>
</div>`;
    // CP.apiFetch   —  fetch() 
    inlineScript = `(async function(){
try{
  var r=await fetch('/wp-json/wp/v2/posts?per_page=5&_fields=id,title,date',{headers:{'Accept':'application/json'}});
  var posts=r.ok?await r.json():[];
  var r2=await fetch('/wp-json/wp/v2/pages?per_page=100&_fields=id',{headers:{'Accept':'application/json'}});
  var pages=r2.ok?await r2.json():[];
  var r3=await fetch('/wp-json/wp/v2/comments?per_page=1&_fields=id',{headers:{'Accept':'application/json'}});
  var commentTotal=r3.ok?(parseInt(r3.headers.get('X-WP-Total')||'0',10)):0;
  posts=Array.isArray(posts)?posts:[];
  pages=Array.isArray(pages)?pages:[];
  document.getElementById('admin-glance').innerHTML=
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+posts.length+' </span><a href="/wp-admin/edit.php" style="color:#2271b1"></a></li>'+
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+pages.length+' </span><a href="/wp-admin/edit.php?post_type=page" style="color:#2271b1"></a></li>'+
    '<li style="padding:4px 0;display:flex;justify-content:space-between">'+
    '<span>'+commentTotal+' </span><a href="/wp-admin/edit-comments.php" style="color:#2271b1"></a></li>';
  var actEl=document.getElementById('admin-activity');
  if(!posts.length){actEl.innerHTML='<p style="color:#8c8f94">   . <a href="/wp-admin/post-new.php">   !</a></p>';return;}
  actEl.innerHTML='<ul style="list-style:none;margin:0;padding:0">'+posts.map(function(p){
    var d=new Date(p.date).toLocaleDateString('ko-KR');
    var t=(p.title&&p.title.rendered)||'( )';
    return '<li style="padding:5px 0;border-bottom:1px solid #f0f0f1">'+
      '<a href="/wp-admin/post.php?post='+p.id+'&action=edit" style="color:#2271b1">'+t+'</a>'+
      '<span style="float:right;color:#8c8f94;font-size:.8rem">'+d+'</span></li>';
  }).join('')+'</ul>';
}catch(e){
  document.getElementById('admin-glance').innerHTML='<li style="color:#d63638">  </li>';
  document.getElementById('admin-activity').textContent=': '+e.message;
}
})();`;

  } else if (page === 'edit') {
    pageTitle = isPage ? '' : '';
    const newHref = isPage ? '/wp-admin/post-new.php?post_type=page' : '/wp-admin/post-new.php';
    const apiType = isPage ? 'pages' : 'posts';
    const emptyMsg = isPage ? '  .' : '  .';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:10px">
      <a href="${newHref}" class="btn-wp"> ${isPage ? '' : ''} </a>
    </div>
    <table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <td style="width:30px;padding:8px 10px"><input type="checkbox" id="cb-select-all"></td>
        <th style="padding:8px 10px;text-align:left;font-size:.875rem"></th>
        <th style="padding:8px 10px;text-align:left;font-size:.875rem;width:120px"></th>
      </tr></thead>
      <tbody id="posts-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94"> ...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/${apiType}?per_page=50&_fields=id,title,date,status,link&status=publish,draft,future,private,pending',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var posts=r.ok?await r.json():[];
posts=Array.isArray(posts)?posts:[];
var el=document.getElementById('posts-list');
if(!posts.length){
  el.innerHTML='<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94">${emptyMsg} <a href="${newHref}"> </a></td></tr>';
  return;
}
el.innerHTML=posts.map(function(p){
  var title=(p.title&&p.title.rendered)||'( )';
  var d=new Date(p.date).toLocaleDateString('ko-KR');
  var editHref='/wp-admin/post.php?post='+p.id+'&action=edit';
  var statusLabel={publish:'',draft:'',private:'',future:'',pending:' ',trash:''}[p.status]||p.status;
  var statusColor={publish:'#00a32a',draft:'#8c8f94',private:'#3858e9',future:'#f0ad00',pending:'#996800',trash:'#d63638'}[p.status]||'#8c8f94';
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:8px 10px"><input type="checkbox"></td>'+
    '<td style="padding:8px 10px"><strong><a href="'+editHref+'" style="color:#2271b1;text-decoration:none">'+title+'</a></strong>'+
    '<div style="font-size:.8rem;color:#8c8f94;margin-top:3px">'+
    '<a href="'+editHref+'"></a> | '+
    '<a href="#" onclick="trashPost('+p.id+',this);return false;" style="color:#b32d2e"></a> | '+
    '<a href="'+(p.link||'/')+ '" target="_blank"></a></div></td>'+
    '<td style="padding:8px 10px;font-size:.8rem;color:'+statusColor+'">'+statusLabel+'<br><span style="color:#50575e">'+d+'</span></td>'+
    '</tr>';
}).join('');
})();
async function trashPost(id,el){
  if(!confirm('   ?'))return;
  var r=await fetch('/wp-json/wp/v2/${apiType}/'+id,{method:'DELETE',headers:{'Content-Type':'application/json'}}).catch(function(){return{ok:false};});
  if(r.ok){el.closest('tr').remove();}else{alert(' ');}
}`;

  } else if (page === 'post-new' || page === 'post') {
    const isEdit = page === 'post' && sp && sp.get('action') === 'edit';
    const postId = sp ? sp.get('post') : null;
    pageTitle = isEdit ? ' ' : '  ';
    bodyHtml = `
<style>
#block-toolbar{display:flex;flex-wrap:wrap;gap:2px;padding:6px 8px;background:#fff;border:1px solid #dcdcde;border-radius:4px;margin-bottom:8px;align-items:center}
.tb-btn{padding:4px 7px;background:none;border:1px solid transparent;border-radius:3px;cursor:pointer;font-size:.8rem;color:#1d2327;min-width:28px;display:inline-flex;align-items:center;justify-content:center;transition:background .1s}
.tb-btn:hover{background:#f0f0f0;border-color:#c3c4c7}
.tb-btn.active{background:#e7f0f8;border-color:#2271b1;color:#2271b1}
.tb-sep{width:1px;background:#dcdcde;height:20px;margin:0 4px}
.tb-select{padding:3px 6px;border:1px solid #c3c4c7;border-radius:3px;font-size:.8rem;color:#1d2327;background:#fff;height:26px}
#post-editor{min-height:400px;border:1px solid #dcdcde;border-radius:4px;padding:20px;font-size:.9375rem;line-height:1.8;outline:none;background:#fff;color:#1d2327}
#post-editor:focus{border-color:#2271b1;box-shadow:0 0 0 1px #2271b1}
#post-editor [data-block]{position:relative}
#post-editor h1{font-size:2em;font-weight:700;margin:.5em 0}
#post-editor h2{font-size:1.6em;font-weight:700;margin:.5em 0}
#post-editor h3{font-size:1.3em;font-weight:700;margin:.5em 0}
#post-editor h4{font-size:1.1em;font-weight:700;margin:.5em 0}
#post-editor h5{font-size:1em;font-weight:700;margin:.5em 0}
#post-editor h6{font-size:.9em;font-weight:700;margin:.5em 0}
#post-editor blockquote{border-left:4px solid #2271b1;margin:1em 0;padding:.5em 1em;background:#f0f6fc;color:#50575e;font-style:italic}
#post-editor pre,#post-editor code{background:#1d2327;color:#f0f0f1;padding:.2em .4em;border-radius:3px;font-family:monospace;font-size:.85em}
#post-editor pre{display:block;padding:1em;overflow-x:auto;white-space:pre-wrap}
#post-editor ul,#post-editor ol{padding-left:2em;margin:.5em 0}
#post-editor table{border-collapse:collapse;width:100%;margin:1em 0}
#post-editor table td,#post-editor table th{border:1px solid #c3c4c7;padding:.4em .6em}
#post-editor table th{background:#f6f7f7;font-weight:600}
#post-editor hr{border:none;border-top:2px solid #dcdcde;margin:1.5em 0}
#post-editor .wp-block-button{display:inline-block;background:#2271b1;color:#fff;padding:.5em 1.2em;border-radius:4px;text-decoration:none;font-weight:600;margin:.25em 0}
#post-editor img{max-width:100%;height:auto;display:block;margin:.5em 0}
.block-inserter{padding:4px;background:#f6f7f7;border:1px dashed #c3c4c7;border-radius:4px;text-align:center;cursor:pointer;font-size:.8rem;color:#8c8f94;margin-top:4px;transition:all .2s}
.block-inserter:hover{background:#e7f0f8;border-color:#2271b1;color:#2271b1}
#schedule-row{display:none;margin-top:8px;padding-top:8px;border-top:1px solid #f0f0f1}
</style>

<div id="post-editor-wrap" style="display:grid;grid-template-columns:1fr 300px;gap:20px">
  <div>
    <input type="text" id="post-title" placeholder=" " style="width:100%;font-size:1.5rem;font-weight:700;border:none;border-bottom:2px solid #dcdcde;padding:10px 0;margin-bottom:16px;outline:none;color:#1d2327;background:transparent;transition:border-color .2s" onfocus="this.style.borderColor='#2271b1'" onblur="this.style.borderColor='#dcdcde'">
    
    <div id="block-toolbar">
      <select class="tb-select" id="tb-heading" onchange="insertHeading(this.value)" title=" ">
        <option value=""></option>
        <option value="h1"> 1</option>
        <option value="h2"> 2</option>
        <option value="h3"> 3</option>
        <option value="h4"> 4</option>
        <option value="h5"> 5</option>
        <option value="h6"> 6</option>
      </select>
      <div class="tb-sep"></div>
      <button class="tb-btn" onclick="execFmt('bold')" title=" (Ctrl+B)"><b>B</b></button>
      <button class="tb-btn" onclick="execFmt('italic')" title=" (Ctrl+I)"><i>I</i></button>
      <button class="tb-btn" onclick="execFmt('underline')" title=" (Ctrl+U)"><u>U</u></button>
      <button class="tb-btn" onclick="execFmt('strikeThrough')" title=""><s>S</s></button>
      <div class="tb-sep"></div>
      <button class="tb-btn" onclick="execFmt('insertUnorderedList')" title=" ">≡</button>
      <button class="tb-btn" onclick="execFmt('insertOrderedList')" title=" ">1.</button>
      <div class="tb-sep"></div>
      <button class="tb-btn" onclick="insertBlock('blockquote')" title="">&ldquo;</button>
      <button class="tb-btn" onclick="insertBlock('code')" title="">&lt;/&gt;</button>
      <button class="tb-btn" onclick="insertBlock('pre')" title=" ">PRE</button>
      <button class="tb-btn" onclick="insertBlock('hr')" title="">HR</button>
      <div class="tb-sep"></div>
      <button class="tb-btn" onclick="insertBlock('table')" title=""></button>
      <button class="tb-btn" onclick="insertBlock('button')" title=""></button>
      <button class="tb-btn" onclick="insertImageBlock()" title=""></button>
      <div class="tb-sep"></div>
      <button class="tb-btn" onclick="execFmt('justifyLeft')" title=" ">&#8676;</button>
      <button class="tb-btn" onclick="execFmt('justifyCenter')" title=" ">&#8801;</button>
      <button class="tb-btn" onclick="execFmt('justifyRight')" title=" ">&#8677;</button>
      <div class="tb-sep"></div>
      <button class="tb-btn" onclick="insertLink()" title=""></button>
      <button class="tb-btn" onclick="execFmt('removeFormat')" title=" ">T&#x336;</button>
    </div>
    
    <div id="post-editor" contenteditable="true" spellcheck="true"></div>
    <div id="post-status-bar" style="margin-top:6px;font-size:.8rem;color:#8c8f94"> :  </div>
  </div>
  
  <div>
    <div class="admin-widget" style="margin-bottom:16px">
      <h3 class="widget-title"></h3>
      <div class="widget-body">
        <div style="margin-bottom:10px">
          <label style="font-size:.85rem;font-weight:600;color:#1d2327;display:block;margin-bottom:4px"></label>
          <select id="post-status" onchange="toggleSchedule(this.value)" style="width:100%;padding:5px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.85rem">
            <option value="publish"></option>
            <option value="draft"> </option>
            <option value="private"></option>
            <option value="future"> </option>
          </select>
        </div>
        <div id="schedule-row">
          <label style="font-size:.85rem;font-weight:600;color:#1d2327;display:block;margin-bottom:4px"> /</label>
          <input type="datetime-local" id="post-schedule" style="width:100%;padding:5px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.85rem">
          <div style="font-size:.75rem;color:#8c8f94;margin-top:4px">      .</div>
        </div>
        <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
          <button onclick="savePost()" class="btn-wp" style="flex:1" id="btn-publish"></button>
          <button onclick="saveDraft()" class="btn-wp btn-secondary" style="flex:1"></button>
        </div>
        ${isEdit && postId ? `<div style="margin-top:8px;font-size:.8rem;text-align:center"><a href="/" target="_blank" style="color:#2271b1"> </a></div>` : ''}
      </div>
    </div>
    
    <div class="admin-widget" style="margin-bottom:16px">
      <h3 class="widget-title"></h3>
      <div class="widget-body">
        <textarea id="post-excerpt" placeholder="  ()" rows="3" style="width:100%;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.85rem;resize:vertical"></textarea>
      </div>
    </div>

    <div class="admin-widget" style="margin-bottom:16px">
      <h3 class="widget-title"></h3>
      <div class="widget-body" id="cats-list" style="font-size:.875rem;color:#50575e"> ...</div>
    </div>
    
    <div class="admin-widget" style="margin-bottom:16px">
      <h3 class="widget-title"></h3>
      <div class="widget-body">
        <input type="text" id="post-tags" placeholder="  ( )" style="width:100%;padding:5px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.85rem">
        <div style="font-size:.75rem;color:#8c8f94;margin-top:4px">   .</div>
      </div>
    </div>
    
    <div class="admin-widget">
      <h3 class="widget-title"></h3>
      <div class="widget-body">
        <input type="text" id="post-slug" placeholder="  ( )" style="width:100%;padding:5px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.85rem">
        <div style="font-size:.75rem;color:#8c8f94;margin-top:4px">   .</div>
      </div>
    </div>
  </div>
</div>`;

    inlineScript = `
var _postId=${postId ? parseInt(postId,10) : 0};
var _autoSaveTimer=null;

//    
function toggleSchedule(val){
  var row=document.getElementById('schedule-row');
  var btn=document.getElementById('btn-publish');
  row.style.display=(val==='future')?'block':'none';
  btn.textContent=(val==='future')?' ':'';
  if(val==='future'){
    var d=new Date(Date.now()+60*60*1000);
    var pad=function(n){return n<10?'0'+n:n;};
    document.getElementById('post-schedule').value=d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes());
  }
}

//     
function execFmt(cmd,val){
  document.getElementById('post-editor').focus();
  document.execCommand(cmd,false,val||null);
  document.getElementById('post-editor').focus();
}

function insertHeading(tag){
  var sel=document.getElementById('tb-heading');
  if(!tag){sel.value='';execFmt('formatBlock','p');return;}
  execFmt('formatBlock',tag);
  sel.value='';
}

function insertBlock(type){
  var editor=document.getElementById('post-editor');
  editor.focus();
  var html='';
  if(type==='blockquote'){
    document.execCommand('formatBlock',false,'blockquote');
  } else if(type==='code'){
    document.execCommand('insertHTML',false,'<code> </code>');
  } else if(type==='pre'){
    document.execCommand('insertHTML',false,'<pre>  </pre>');
  } else if(type==='hr'){
    document.execCommand('insertHTML',false,'<hr>');
  } else if(type==='table'){
    document.execCommand('insertHTML',false,'<table><thead><tr><th>1</th><th>2</th><th>3</th></tr></thead><tbody><tr><td>1</td><td>2</td><td>3</td></tr><tr><td>4</td><td>5</td><td>6</td></tr></tbody></table><p><br></p>');
  } else if(type==='button'){
    document.execCommand('insertHTML',false,'<a class="wp-block-button" href="#"> </a>&nbsp;');
  }
}

function insertImageBlock(){
  var url=prompt(' URL :');
  if(!url)return;
  var alt=prompt(' (alt)  ():','');
  document.getElementById('post-editor').focus();
  document.execCommand('insertHTML',false,'<img src="'+url+'" alt="'+(alt||'')+'" style="max-width:100%;height:auto;display:block;margin:.5em 0"><p><br></p>');
}

function insertLink(){
  var url=prompt(' URL :','https://');
  if(!url)return;
  var text=prompt('  :','');
  document.getElementById('post-editor').focus();
  var sel=window.getSelection();
  if(sel&&sel.toString()){
    document.execCommand('createLink',false,url);
  } else {
    document.execCommand('insertHTML',false,'<a href="'+url+'">'+text+'</a>');
  }
}

//  
(async function(){
  var r=await fetch('/wp-json/wp/v2/categories?per_page=50',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
  var cats=r.ok?await r.json():[];
  cats=Array.isArray(cats)?cats:[];
  var el=document.getElementById('cats-list');
  if(!cats.length){
    el.innerHTML='<div style="font-size:.8rem;color:#8c8f94">  <a href="/wp-admin/edit-tags.php?taxonomy=category" style="color:#2271b1"></a></div>';
    return;
  }
  el.innerHTML=cats.map(function(c){return '<label style="display:flex;align-items:center;gap:6px;padding:4px 0"><input type="checkbox" value="'+c.id+'" class="cat-cb" style="accent-color:#2271b1"> '+c.name+'</label>';}).join('');
})();

//   
${isEdit && postId ? `(async function(){
  var r=await fetch('/wp-json/wp/v2/posts/${postId}',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
  if(!r.ok)return;
  var p=await r.json();
  document.getElementById('post-title').value=(p.title&&p.title.rendered)||'';
  document.getElementById('post-editor').innerHTML=(p.content&&p.content.raw)||(p.content&&p.content.rendered)||'';
  var status=p.status||'publish';
  document.getElementById('post-status').value=status;
  toggleSchedule(status);
  if(status==='future'&&p.date){document.getElementById('post-schedule').value=p.date.slice(0,16);}
  if(p.excerpt&&p.excerpt.raw)document.getElementById('post-excerpt').value=p.excerpt.raw;
  if(p.slug)document.getElementById('post-slug').value=p.slug;
  //  
  if(p.categories&&p.categories.length){
    setTimeout(function(){
      p.categories.forEach(function(cid){
        var cb=document.querySelector('.cat-cb[value="'+cid+'"]');
        if(cb)cb.checked=true;
      });
    },600);
  }
})();` : ''}

//  
document.getElementById('post-editor').addEventListener('input',function(){
  clearTimeout(_autoSaveTimer);
  document.getElementById('post-status-bar').textContent=' :  ...';
  _autoSaveTimer=setTimeout(function(){autoSave();},3000);
});

//  
document.getElementById('post-editor').addEventListener('keydown',function(e){
  if((e.ctrlKey||e.metaKey)&&e.key==='b'){e.preventDefault();execFmt('bold');}
  if((e.ctrlKey||e.metaKey)&&e.key==='i'){e.preventDefault();execFmt('italic');}
  if((e.ctrlKey||e.metaKey)&&e.key==='u'){e.preventDefault();execFmt('underline');}
  if((e.ctrlKey||e.metaKey)&&e.key==='s'){e.preventDefault();saveDraft();}
});

async function autoSave(){
  var title=document.getElementById('post-title').value;
  var content=document.getElementById('post-editor').innerHTML;
  if(!title&&!content)return;
  document.getElementById('post-status-bar').textContent='  ...';
  try{
    var method=_postId?'PATCH':'POST';
    var endpoint=_postId?'/wp-json/wp/v2/posts/'+_postId:'/wp-json/wp/v2/posts';
    var r=await fetch(endpoint,{
      method:method,
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body:JSON.stringify({title:title,content:content,status:'draft'})
    });
    if(r.ok){
      var d=await r.json();
      if(!_postId&&d.id){_postId=d.id;history.replaceState(null,'','/wp-admin/post.php?post='+d.id+'&action=edit');}
      document.getElementById('post-status-bar').textContent=' : '+new Date().toLocaleTimeString('ko-KR');
    }
  }catch(e){document.getElementById('post-status-bar').textContent='  ';}
}

async function savePost(){await _save('publish');}
async function saveDraft(){await _save('draft');}

async function _save(status){
  var title=document.getElementById('post-title').value.trim();
  var content=document.getElementById('post-editor').innerHTML.trim();
  var selStatus=document.getElementById('post-status').value||status;
  if(!title){alert(' .');document.getElementById('post-title').focus();return;}
  var cats=[];
  document.querySelectorAll('.cat-cb:checked').forEach(function(el){cats.push(parseInt(el.value,10));});
  var customSlug=document.getElementById('post-slug').value.trim();
  var slug=customSlug||title.toLowerCase().replace(/[^a-z0-9-]+/g,'-').replace(/^-|-$/g,'');
  var excerpt=document.getElementById('post-excerpt').value.trim();
  var payload={title:title,content:content,status:selStatus,slug:slug,categories:cats};
  if(excerpt)payload.excerpt=excerpt;
  // 
  if(selStatus==='future'){
    var schedVal=document.getElementById('post-schedule').value;
    if(!schedVal){alert(' / .');return;}
    var schedDate=new Date(schedVal);
    if(schedDate<=new Date()){alert('     .');return;}
    payload.date=schedDate.toISOString();
    payload.date_gmt=schedDate.toISOString();
  }
  var method=_postId?'PATCH':'POST';
  var endpoint=_postId?'/wp-json/wp/v2/posts/'+_postId:'/wp-json/wp/v2/posts';
  try{
    var r=await fetch(endpoint,{
      method:method,
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body:JSON.stringify(payload)
    });
    var d=await r.json();
    if(r.ok&&d.id){
      var msg=selStatus==='publish'?'!':selStatus==='future'?'  !':' .';
      alert(msg);
      window.location.href='/wp-admin/edit.php';
    }else{alert(' : '+(d.message||JSON.stringify(d)));}
  }catch(e){alert(': '+e.message);}
}`;

  } else if (page === 'upload') {
    pageTitle = ' ';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:15px;display:flex;align-items:center;gap:10px">
      <label class="btn-wp" style="cursor:pointer">  
        <input type="file" id="file-input" style="display:none" accept="image/*,video/*,audio/*,.pdf" multiple>
      </label>
      <div id="upload-progress" style="display:none;font-size:.85rem;color:#2271b1"> ...</div>
    </div>
    <div id="media-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px">
      <div style="text-align:center;padding:40px;color:#8c8f94;grid-column:1/-1"> ...</div>
    </div>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/media?per_page=30',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var media=r.ok?await r.json():[];
media=Array.isArray(media)?media:[];
var el=document.getElementById('media-grid');
if(!media.length){el.innerHTML='<div style="text-align:center;padding:60px;color:#8c8f94;grid-column:1/-1"><p style="font-size:1.5rem;margin-bottom:8px">[ ]</p><p>  .</p></div>';return;}
el.innerHTML=media.map(function(m){
  var src=m.source_url||(m.guid&&m.guid.rendered)||'';
  var isImg=(m.mime_type||'').startsWith('image/');
  var ttl=(m.title&&m.title.rendered)||m.slug||'';
  return '<div style="border:1px solid #dcdcde;border-radius:4px;overflow:hidden;background:#f6f7f7;cursor:pointer" onclick="showMediaDetail(this)" data-url="'+src+'" data-title="'+ttl+'">'+
    (isImg?'<img src="'+src+'" style="width:100%;height:130px;object-fit:cover;display:block">':
    '<div style="height:130px;display:flex;align-items:center;justify-content:center;font-size:1rem;color:#8c8f94"></div>')+
    '<p style="margin:0;padding:5px 7px;font-size:.75rem;color:#1d2327;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+ttl+'</p>'+
    '</div>';
}).join('');
})();

document.getElementById('file-input').addEventListener('change',async function(){
  var files=Array.from(this.files);
  if(!files.length)return;
  var prog=document.getElementById('upload-progress');
  prog.style.display='block';
  for(var i=0;i<files.length;i++){
    prog.textContent=' : '+(i+1)+'/'+files.length;
    var fd=new FormData();fd.append('file',files[i]);fd.append('title',files[i].name);
    await fetch('/wp-admin/async-upload.php',{method:'POST',body:fd}).catch(function(){});
  }
  prog.style.display='none';
  location.reload();
});

function showMediaDetail(el){
  var url=el.getAttribute('data-url');
  var title=el.getAttribute('data-title');
  if(url)prompt(' URL ():',url);
}`;

  } else if (page === 'themes' || page === 'theme-install') {
    pageTitle = page === 'theme-install' ? '  ' : '';
    // Twenty Twenty-Five  WP    (theme.json )
    const builtinThemes = [
      { slug:'twentytwentyfive', name:'Twenty Twenty-Five', ver:'1.4', active:true,
        desc:'    .  , ,   .',
        colors:['#FFFFFF','#111111','#FFEE58','#F6CFF4','#503AA8'],
        screenshot:'linear-gradient(135deg,#FBFAF3 50%,#FFEE58 100%)',
        tags:[' ','  ','']},
      { slug:'twentytwentyfour', name:'Twenty Twenty-Four', ver:'1.3',
        desc:'   .    .',
        colors:['#FAFAFA','#1A1A1A','#D1E4DD'],
        screenshot:'linear-gradient(135deg,#FAFAFA 50%,#D1E4DD 100%)',
        tags:[' ','  ']},
      { slug:'twentytwentythree', name:'Twenty Twenty-Three', ver:'1.5',
        desc:'   .   .',
        colors:['#FFFFFF','#000000','#CDDCE8'],
        screenshot:'linear-gradient(135deg,#fff 50%,#CDDCE8 100%)',
        tags:[' ','']},
      { slug:'astra', name:'Astra', ver:'4.8',
        desc:'(< 50KB)  . WooCommerce  .',
        colors:['#ffffff','#3a3a3a','#4169e1'],
        screenshot:'linear-gradient(135deg,#ffffff 50%,#4169e1 100%)',
        tags:['','WooCommerce',' ']},
      { slug:'generatepress', name:'GeneratePress', ver:'3.4',
        desc:'  .    .',
        colors:['#ffffff','#252525','#1b8be0'],
        screenshot:'linear-gradient(135deg,#f5f5f5 50%,#1b8be0 100%)',
        tags:['','',' ']},
      { slug:'kadence', name:'Kadence', ver:'1.2',
        desc:' . /  .',
        colors:['#ffffff','#1a1a1a','#3182CE'],
        screenshot:'linear-gradient(135deg,#f0f0f0 50%,#3182CE 100%)',
        tags:[' ','','']},
    ];
    if (page === 'theme-install') {
      bodyHtml = `
<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap">
  <h2 style="margin:0;font-size:1.1rem">   </h2>
  <div style="flex:1;max-width:300px">
    <input type="text" id="theme-search" placeholder="WordPress.org  …" 
      style="width:100%;padding:7px 12px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"
      oninput="searchThemes(this.value)">
  </div>
  <button onclick="toggleThemeZip()" style="padding:6px 12px;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem;background:#f6f7f7;color:#1e1e1e" id="btn-theme-zip">ZIP </button>
  <a href="/wp-admin/themes.php" style="font-size:.875rem;color:#2271b1">←  </a>
</div>

<div id="theme-zip-panel" style="display:none;margin-bottom:20px;background:#fff;border:1px solid #c3c4c7;border-radius:6px;padding:20px">
  <h3 style="font-size:.95rem;margin:0 0 10px;font-weight:600">ZIP   </h3>
  <div id="theme-zip-drop" ondragover="event.preventDefault();this.style.borderColor='#2271b1'" ondragleave="this.style.borderColor='#c3c4c7'" ondrop="handleThemeZipDrop(event)" style="border:2px dashed #c3c4c7;border-radius:6px;padding:24px;text-align:center;cursor:pointer" onclick="document.getElementById('theme-zip-input').click()">
    <div style="font-size:2rem;margin-bottom:6px">[]</div>
    <div style="font-size:.9rem;font-weight:600"> ZIP    </div>
    <div style="font-size:.8rem;color:#8c8f94;margin-top:4px"> 32MB</div>
    <input type="file" id="theme-zip-input" accept=".zip" style="display:none" onchange="handleThemeZipFile(this.files[0])">
  </div>
  <div id="theme-zip-info" style="display:none;margin-top:10px;padding:10px;background:#f6f7f7;border-radius:4px;font-size:.85rem"></div>
  <div id="theme-zip-result" style="display:none;margin-top:10px;padding:10px 14px;border-radius:4px;font-size:.85rem"></div>
  <div style="margin-top:12px;display:flex;gap:8px">
    <button onclick="installThemeZip()" id="btn-theme-zip-install" class="btn-wp" disabled style="opacity:.5"></button>
    <button onclick="toggleThemeZip()" class="btn-wp btn-secondary"></button>
  </div>
</div>

<div id="theme-search-notice" style="display:none;padding:10px 14px;background:#e7f3ff;border:1px solid #72aee6;border-radius:4px;margin-bottom:16px;font-size:.875rem"></div>
<div id="themes-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:20px">
  ${builtinThemes.map(t => `
  <div class="theme-card" data-slug="${t.slug}" style="border:1px solid #c3c4c7;border-radius:6px;overflow:hidden;background:#fff;transition:box-shadow .2s" onmouseenter="this.style.boxShadow='0 4px 12px rgba(0,0,0,.12)'" onmouseleave="this.style.boxShadow=''">
    <div style="height:140px;background:${t.screenshot};position:relative">
      <div style="position:absolute;bottom:8px;right:8px;display:flex;gap:4px">
        ${t.colors.map(c=>`<span style="width:16px;height:16px;border-radius:50%;background:${c};border:1px solid rgba(0,0,0,.1)"></span>`).join('')}
      </div>
    </div>
    <div style="padding:14px">
      <h3 style="margin:0 0 5px;font-size:.9375rem">${t.name} <span style="color:#8c8f94;font-weight:400;font-size:.8rem">v${t.ver}</span></h3>
      <p style="margin:0 0 8px;font-size:.8rem;color:#50575e;line-height:1.5">${t.desc}</p>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">
        ${t.tags.map(tag=>`<span style="background:#f0f0f1;color:#50575e;font-size:.7rem;padding:2px 7px;border-radius:20px">${tag}</span>`).join('')}
      </div>
      <div style="display:flex;gap:6px">
        <button onclick="installTheme('${t.slug}','${t.name}',this)" style="flex:1;padding:6px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600"></button>
        <button onclick="previewTheme('${t.slug}')" style="padding:6px 10px;background:#f6f7f7;border:1px solid #ccc;border-radius:4px;cursor:pointer;font-size:.8rem"></button>
      </div>
    </div>
  </div>`).join('')}
</div>
<div id="wp-org-results" style="display:none;margin-top:30px">
  <h3 style="font-size:1rem;margin-bottom:12px">WordPress.org  </h3>
  <div id="wp-org-themes-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:20px"></div>
</div>`;
      inlineScript = `
async function searchThemes(q) {
  const notice = document.getElementById('theme-search-notice');
  if (!q || q.length < 2) { notice.style.display='none'; return; }
  notice.style.display='block'; notice.textContent='WordPress.org   …';
  try {
    const r = await fetch('https://api.wordpress.org/themes/info/1.1/?action=query_themes&request[search]='+encodeURIComponent(q)+'&request[per_page]=8&request[fields][screenshot_url]=1&request[fields][version]=1&request[fields][description]=1&request[fields][tags]=1');
    const data = r.ok ? await r.json() : null;
    const grid = document.getElementById('wp-org-themes-grid');
    const section = document.getElementById('wp-org-results');
    if (data && data.themes && data.themes.length) {
      grid.innerHTML = data.themes.map(t => \`
        <div style="border:1px solid #c3c4c7;border-radius:6px;overflow:hidden;background:#fff">
          <div style="height:120px;background:url('\${t.screenshot_url}') center/cover no-repeat #f0f0f1"></div>
          <div style="padding:12px">
            <h4 style="margin:0 0 5px;font-size:.875rem">\${t.name} <span style="color:#8c8f94;font-size:.75rem">v\${t.version}</span></h4>
            <p style="margin:0 0 8px;font-size:.75rem;color:#50575e;line-height:1.4">\${(t.description||'').replace(/<[^>]+>/g,'').slice(0,100)}…</p>
            <button onclick="installTheme('\${t.slug}','\${t.name.replace(/'/g,'')}',this)" style="width:100%;padding:5px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600"></button>
          </div>
        </div>\`).join('');
      section.style.display='block';
      notice.textContent=\`\${data.themes.length}  .\`;
    } else {
      section.style.display='none';
      notice.textContent='  .';
    }
  } catch(e) { notice.textContent='  : '+e.message; }
}
async function installTheme(slug, name, btn) {
  btn.textContent=' …'; btn.disabled=true;
  try {
    const r = await fetch('/wp-json/cloudpress/v1/themes/install', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({slug, name})
    });
    const d = r.ok ? await r.json() : {success:false};
    if (d.success) {
      btn.textContent=' '; btn.style.background='#00a32a';
      btn.nextElementSibling && (btn.nextElementSibling.textContent = '');
      btn.nextElementSibling && btn.nextElementSibling.setAttribute('onclick', \`activateTheme('\${slug}','\${name}',this)\`);
    } else {
      btn.textContent=''; btn.style.background='#d63638';
    }
  } catch(e) { btn.textContent=''; btn.style.background='#d63638'; }
}
async function activateTheme(slug, name, btn) {
  btn.textContent=' …'; btn.disabled=true;
  const r = await fetch('/wp-json/cloudpress/v1/themes/activate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug, name})
  });
  const d = r.ok ? await r.json() : {success:false};
  if (d.success) { btn.textContent=' '; btn.style.background='#00a32a'; }
  else { btn.textContent=''; btn.disabled=false; }
}
function previewTheme(slug) {
  window.open('/wp-admin/themes.php?preview='+slug, '_blank');
}

//   ZIP  
let _themeZipFile = null;
function toggleThemeZip() {
  const panel = document.getElementById('theme-zip-panel');
  const btn = document.getElementById('btn-theme-zip');
  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';
  btn.style.background = isOpen ? '#f6f7f7' : '#2271b1';
  btn.style.color = isOpen ? '#1e1e1e' : '#fff';
  if (!isOpen) { _themeZipFile=null; document.getElementById('theme-zip-result').style.display='none'; }
}
function handleThemeZipDrop(e) {
  e.preventDefault();
  document.getElementById('theme-zip-drop').style.borderColor='#c3c4c7';
  if (e.dataTransfer.files[0]) handleThemeZipFile(e.dataTransfer.files[0]);
}
function handleThemeZipFile(file) {
  if (!file||!file.name.endsWith('.zip')) { alert('ZIP    .'); return; }
  if (file.size>32*1024*1024) { alert('  32MB .'); return; }
  _themeZipFile=file;
  const info=document.getElementById('theme-zip-info');
  info.style.display='block';
  info.innerHTML=\`<strong> \${file.name}</strong> <span style="color:#8c8f94">(\${(file.size/1024/1024).toFixed(1)} MB)</span>\`;
  const btn=document.getElementById('btn-theme-zip-install');
  btn.disabled=false; btn.style.opacity='1';
  document.getElementById('theme-zip-result').style.display='none';
}
async function installThemeZip() {
  if (!_themeZipFile) return;
  const btn=document.getElementById('btn-theme-zip-install');
  const result=document.getElementById('theme-zip-result');
  btn.textContent=' …'; btn.disabled=true;
  try {
    const ab=await _themeZipFile.arrayBuffer();
    const uint8=new Uint8Array(ab);
    let bin=''; uint8.forEach(b=>bin+=String.fromCharCode(b));
    const base64=btoa(bin);
    const themeName=_themeZipFile.name.replace(/\\.zip$/i,'');
    const slug=themeName.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
    const r=await fetch('/wp-json/cloudpress/v1/themes/install-zip', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({slug,name:themeName,zip_base64:base64,file_name:_themeZipFile.name})
    });
    const d=r.ok?await r.json():{success:false,message:' '};
    result.style.display='block';
    if (d.success) {
      result.style.cssText='display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px';
      result.innerHTML=\` <strong>\${themeName}</strong>  ! <button onclick="activateThemeAfterZip('\${slug}','\${themeName}')" style="margin-left:8px;padding:4px 10px;background:#00a32a;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:.8rem"></button>\`;
      _themeZipFile=null; btn.textContent='';
    } else {
      result.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
      result.textContent='  : '+(d.message||'   ');
      btn.textContent=''; btn.disabled=false; btn.style.opacity='1';
    }
  } catch(e) {
    result.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
    result.textContent=': '+e.message;
    btn.textContent=''; btn.disabled=false; btn.style.opacity='1';
  }
}
async function activateThemeAfterZip(slug,name) {
  const r=await fetch('/wp-json/cloudpress/v1/themes/activate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({slug,name})});
  const d=r.ok?await r.json():{success:false};
  if(d.success){alert(name+' !');location.reload();}
  else{alert(' : '+(d.message||''));}
}`;
    } else {
      //   
      bodyHtml = `
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
  <h2 style="margin:0;font-size:1.1rem"> (${builtinThemes.length})</h2>
  <a href="/wp-admin/theme-install.php" class="btn-wp">  </a>
</div>
<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:20px">
${builtinThemes.map(t => `
  <div style="border:${t.active?'3px solid #2271b1':'1px solid #c3c4c7'};border-radius:6px;overflow:hidden;background:#fff;position:relative;transition:box-shadow .2s" onmouseenter="this.style.boxShadow='0 4px 12px rgba(0,0,0,.15)'" onmouseleave="this.style.boxShadow=''">
    ${t.active?`<span style="position:absolute;top:10px;left:10px;background:#2271b1;color:#fff;font-size:.7rem;font-weight:700;padding:3px 8px;border-radius:20px;z-index:1"> </span>`:''}
    <div style="height:150px;background:${t.screenshot};display:flex;align-items:flex-end;padding:8px;justify-content:flex-end">
      <div style="display:flex;gap:3px">
        ${t.colors.map(c=>`<span style="width:14px;height:14px;border-radius:50%;background:${c};border:1px solid rgba(0,0,0,.1)"></span>`).join('')}
      </div>
    </div>
    <div style="padding:14px">
      <h3 style="margin:0 0 5px;font-size:.9375rem">${t.name} <span style="color:#8c8f94;font-weight:400;font-size:.8rem">v${t.ver}</span></h3>
      <p style="margin:0 0 10px;font-size:.8rem;color:#50575e;line-height:1.5">${t.desc}</p>
      <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:12px">
        ${t.tags.map(tag=>`<span style="background:#f0f0f1;color:#50575e;font-size:.7rem;padding:2px 7px;border-radius:20px">${tag}</span>`).join('')}
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        ${t.active
          ? `<button onclick="customizeTheme()" style="flex:1;padding:7px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600"> </button>`
          : `<button onclick="activateTheme('${t.slug}','${t.name}',this)" style="flex:1;padding:7px;background:#00a32a;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600"></button>`
        }
        <button onclick="window.open('/','_blank')" style="padding:7px 10px;background:#f6f7f7;border:1px solid #ccc;border-radius:4px;cursor:pointer;font-size:.8rem"></button>
        ${!t.active?`<button style="padding:7px 10px;background:#fff;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem;color:#d63638" onclick="if(confirm('${t.name}  ?'))deleteTheme('${t.slug}',this)"></button>`:''}
      </div>
    </div>
  </div>`).join('')}
</div>`;
      inlineScript = `
async function activateTheme(slug, name, btn) {
  if (!confirm(name + '  ?')) return;
  btn.textContent=' …'; btn.disabled=true;
  try {
    const r = await fetch('/wp-json/cloudpress/v1/themes/activate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({slug, name})
    });
    const d = r.ok ? await r.json() : {success:false};
    if (d.success) { location.reload(); }
    else { alert(' : ' + (d.message||'')); btn.textContent=''; btn.disabled=false; }
  } catch(e) { alert(': '+e.message); btn.textContent=''; btn.disabled=false; }
}
async function deleteTheme(slug, btn) {
  const r = await fetch('/wp-json/cloudpress/v1/themes/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug})
  });
  if (r.ok) { btn.closest('[data-slug]')?.remove() || location.reload(); }
}
function customizeTheme() { window.open('/wp-admin/customize.php','_blank'); }`;
    }

  } else if (page === 'plugins' || page === 'plugin-install') {
    pageTitle = page === 'plugin-install' ? '  ' : '';

    if (page === 'plugin-install') {
      //    : WordPress.org API   
      const featuredPlugins = [
        { slug:'woocommerce',     name:'WooCommerce',      ver:'9.4',  active:false, downloads:'200M+',
          desc:'   . , ,  .',
          icon:'', tags:['','',''], stars:4.5},
        { slug:'yoast-seo',       name:'Yoast SEO',        ver:'23.1', active:false, downloads:'300M+',
          desc:'WordPress SEO . On-page SEO, ,  .',
          icon:'', tags:['SEO','',''], stars:4.8},
        { slug:'wordfence',       name:'Wordfence Security', ver:'7.11', active:false, downloads:'150M+',
          desc:',  ,      .',
          icon:'', tags:['','',''], stars:4.7},
        { slug:'contact-form-7',  name:'Contact Form 7',   ver:'5.9',  active:false, downloads:'500M+',
          desc:'     .  .',
          icon:'', tags:['','',''], stars:4.3},
        { slug:'elementor',       name:'Elementor',        ver:'3.25', active:false, downloads:'180M+',
          desc:'    . 100+ ,  .',
          icon:'', tags:[' ','',''], stars:4.6},
        { slug:'jetpack',         name:'Jetpack',          ver:'14.0', active:false, downloads:'400M+',
          desc:', ,    .',
          icon:'', tags:['','',''], stars:4.2},
        { slug:'w3-total-cache',  name:'W3 Total Cache',   ver:'2.7',  active:false, downloads:'50M+',
          desc:'   . CDN, minify, .',
          icon:'', tags:['','CDN',''], stars:4.4},
        { slug:'wpforms-lite',    name:'WPForms Lite',     ver:'1.9',  active:false, downloads:'200M+',
          desc:'  .     .',
          icon:'', tags:['','',''], stars:4.8},
        { slug:'akismet',         name:'Akismet Anti-Spam',ver:'5.3',  active:false,  downloads:'800M+',
          desc:'AI    .',
          icon:'', tags:[' ','AI',''], stars:4.5},
        { slug:'wp-super-cache',  name:'WP Super Cache',   ver:'1.12', active:false, downloads:'60M+',
          desc:'WordPress.org   .  HTML  .',
          icon:'', tags:['','',''], stars:4.3},
        { slug:'classic-editor',  name:'Classic Editor',   ver:'1.6',  active:false, downloads:'700M+',
          desc:' (TinyMCE) .    .',
          icon:'', tags:['','',''], stars:4.7},
        { slug:'tablepress',      name:'TablePress',       ver:'3.0',  active:false, downloads:'40M+',
          desc:'   . Excel/CSV  .',
          icon:'', tags:['','CSV',''], stars:4.8},
      ];

      bodyHtml = `
<div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
  <h2 style="margin:0;font-size:1.1rem"> </h2>
  <div style="flex:1;max-width:360px;position:relative">
    <input type="text" id="plugin-search" placeholder="WordPress.org  …" 
      style="width:100%;padding:7px 36px 7px 12px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"
      oninput="debounceSearch(this.value)">
    <span style="position:absolute;right:10px;top:50%;transform:translateY(-50%);color:#8c8f94"></span>
  </div>
  <div style="display:flex;gap:6px">
    <button onclick="filterPlugins('featured')" id="tab-featured" class="plugin-tab active-tab" style="padding:6px 12px;border:1px solid #2271b1;border-radius:4px;cursor:pointer;font-size:.8rem;background:#2271b1;color:#fff"></button>
    <button onclick="filterPlugins('popular')" id="tab-popular" class="plugin-tab" style="padding:6px 12px;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem;background:#f6f7f7;color:#1e1e1e"></button>
    <button onclick="filterPlugins('new')" id="tab-new" class="plugin-tab" style="padding:6px 12px;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem;background:#f6f7f7;color:#1e1e1e"></button>
    <button onclick="toggleZipUpload()" id="tab-zip" class="plugin-tab" style="padding:6px 12px;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem;background:#f6f7f7;color:#1e1e1e">ZIP </button>
  </div>
  <a href="/wp-admin/plugins.php" style="font-size:.875rem;color:#2271b1;margin-left:auto">←  </a>
</div>

<div id="zip-upload-panel" style="display:none;margin-bottom:20px;background:#fff;border:1px solid #c3c4c7;border-radius:6px;padding:20px">
  <h3 style="font-size:.95rem;margin:0 0 12px;font-weight:600">ZIP   </h3>
  <p style="font-size:.85rem;color:#50575e;margin:0 0 14px">WordPress.org     ZIP    .</p>
  <div id="zip-drop-zone" ondragover="event.preventDefault();this.style.borderColor='#2271b1'" ondragleave="this.style.borderColor='#c3c4c7'" ondrop="handleZipDrop(event)" style="border:2px dashed #c3c4c7;border-radius:6px;padding:30px;text-align:center;transition:border-color .2s;cursor:pointer" onclick="document.getElementById('plugin-zip-input').click()">
    <div style="font-size:2.5rem;margin-bottom:8px">[ZIP]</div>
    <div style="font-size:.9rem;font-weight:600;margin-bottom:4px">ZIP     </div>
    <div style="font-size:.8rem;color:#8c8f94"> ZIP   ( 32MB)</div>
    <input type="file" id="plugin-zip-input" accept=".zip" style="display:none" onchange="handleZipFile(this.files[0])">
  </div>
  <div id="zip-info" style="display:none;margin-top:12px;padding:12px;background:#f6f7f7;border-radius:4px;font-size:.85rem"></div>
  <div id="zip-progress" style="display:none;margin-top:10px">
    <div style="background:#e0e0e0;border-radius:4px;height:6px;overflow:hidden">
      <div id="zip-progress-bar" style="background:#2271b1;height:100%;width:0;transition:width .3s"></div>
    </div>
    <div id="zip-progress-text" style="font-size:.8rem;color:#8c8f94;margin-top:4px;text-align:center"> ...</div>
  </div>
  <div id="zip-result" style="display:none;margin-top:10px;padding:10px 14px;border-radius:4px;font-size:.85rem"></div>
  <div style="margin-top:14px;display:flex;gap:8px">
    <button onclick="installZipPlugin()" id="btn-zip-install" class="btn-wp" disabled style="opacity:.5"></button>
    <button onclick="toggleZipUpload()" class="btn-wp btn-secondary"></button>
  </div>
</div>

<div id="search-results-bar" style="display:none;padding:10px 14px;background:#e7f3ff;border:1px solid #72aee6;border-radius:4px;margin-bottom:16px;font-size:.875rem"></div>

<div id="plugin-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px">
  ${featuredPlugins.map(p => `
  <div class="plugin-install-card" data-slug="${p.slug}" data-tags="${p.tags.join(',')}" style="border:1px solid #c3c4c7;border-radius:6px;background:#fff;padding:16px;display:flex;flex-direction:column;gap:10px;transition:box-shadow .2s" onmouseenter="this.style.boxShadow='0 2px 8px rgba(0,0,0,.1)'" onmouseleave="this.style.boxShadow=''">
    <div style="display:flex;align-items:flex-start;gap:12px">
      <div style="width:48px;height:48px;display:flex;align-items:center;justify-content:center;background:#f6f7f7;border-radius:8px;flex-shrink:0">${p.icon ? `<img src="${p.icon}" style="width:100%;height:100%;object-fit:contain;border-radius:8px">` : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" width="24" height="24" fill="#8c8f94"><path d="M18 8h-2V6c0-1.1-.9-2-2-2h-1V2h-2v2H9V2H7v2H6C4.9 4 4 4.9 4 6v2H2v2h2v1H2v2h2v1c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2v-1h2v-2h-2v-1h2V8zm-4 7H6V6h10v9z"/></svg>`}</div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
          <strong style="font-size:.9375rem">${p.name}</strong>
          <span style="color:#8c8f94;font-size:.75rem">v${p.ver}</span>
          ${p.active?`<span style="background:#00a32a;color:#fff;font-size:.65rem;padding:2px 6px;border-radius:20px"></span>`:''}
        </div>
        <div style="color:#8c8f94;font-size:.75rem;margin-top:2px">: ${p.downloads}</div>
      </div>
    </div>
    <p style="margin:0;font-size:.8rem;color:#50575e;line-height:1.5;flex:1">${p.desc}</p>
    <div style="display:flex;flex-wrap:wrap;gap:4px">
      ${p.tags.map(tag=>`<span style="background:#f0f0f1;color:#50575e;font-size:.7rem;padding:2px 7px;border-radius:20px">${tag}</span>`).join('')}
    </div>
    <div style="display:flex;align-items:center;gap:6px">
      <div style="flex:1;font-size:.75rem;color:#f0ad00">
        ${''.repeat(Math.floor(p.stars))}${''.repeat(5-Math.floor(p.stars))} <span style="color:#8c8f94">${p.stars}</span>
      </div>
      ${p.active
        ? `<button onclick="activatePlugin('${p.slug}','${p.name}',this)" style="padding:6px 14px;background:#00a32a;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600"></button>`
        : `<button onclick="installPlugin('${p.slug}','${p.name}',this)" style="padding:6px 14px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600"> </button>`
      }
      <button onclick="window.open('https://wordpress.org/plugins/${p.slug}/','_blank')" style="padding:6px 10px;background:#f6f7f7;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem"> </button>
    </div>
  </div>`).join('')}
</div>

<div id="wp-org-plugin-results" style="display:none;margin-top:24px">
  <h3 id="wp-org-results-title" style="font-size:1rem;margin-bottom:12px"></h3>
  <div id="wp-org-plugin-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px"></div>
  <div id="wp-org-loading" style="display:none;text-align:center;padding:30px;color:#8c8f94">WordPress.org  …</div>
</div>`;

      inlineScript = `
let searchTimer = null;
function debounceSearch(q) {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => searchPlugins(q), 500);
}

async function searchPlugins(q) {
  const bar = document.getElementById('search-results-bar');
  const section = document.getElementById('wp-org-plugin-results');
  const loading = document.getElementById('wp-org-loading');
  const grid = document.getElementById('wp-org-plugin-grid');
  const title = document.getElementById('wp-org-results-title');
  const mainGrid = document.getElementById('plugin-grid');

  if (!q || q.length < 2) {
    bar.style.display='none'; section.style.display='none';
    mainGrid.style.display=''; return;
  }

  //   
  document.querySelectorAll('.plugin-install-card').forEach(card => {
    const match = card.dataset.slug.includes(q.toLowerCase()) ||
                  card.querySelector('strong').textContent.toLowerCase().includes(q.toLowerCase()) ||
                  card.querySelector('p').textContent.toLowerCase().includes(q.toLowerCase());
    card.style.display = match ? '' : 'none';
  });

  // WordPress.org API 
  bar.style.display='block'; bar.textContent='WordPress.org  …';
  section.style.display='block'; loading.style.display='block'; grid.innerHTML='';

  try {
    const url = 'https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request[search]='
              + encodeURIComponent(q) + '&request[per_page]=12&request[fields][short_description]=1&request[fields][icons]=1&request[fields][downloaded]=1&request[fields][rating]=1&request[fields][num_ratings]=1&request[fields][active_installs]=1&request[fields][tags]=1&request[fields][version]=1';
    const r = await fetch(url);
    loading.style.display='none';
    if (r.ok) {
      const data = await r.json();
      const plugins = data.plugins || [];
      if (plugins.length) {
        title.textContent = 'WordPress.org  : ' + plugins.length + '';
        grid.innerHTML = plugins.map(p => {
          const icon = (p.icons && (p.icons['1x'] || p.icons.default)) || '';
          const stars = Math.round((p.rating||0)/20);
          const installs = p.active_installs >= 1000000 ? Math.floor(p.active_installs/1000000)+'M+' : p.active_installs >= 1000 ? Math.floor(p.active_installs/1000)+'K+' : p.active_installs+'';
          const tags = Object.values(p.tags||{}).slice(0,3);
          return \`<div style="border:1px solid #c3c4c7;border-radius:6px;background:#fff;padding:16px;display:flex;flex-direction:column;gap:10px">
            <div style="display:flex;align-items:flex-start;gap:12px">
              <div style="width:48px;height:48px;border-radius:8px;overflow:hidden;background:#f6f7f7;flex-shrink:0">\${icon?'<img src="'+icon+'" style="width:100%;height:100%;object-fit:cover">':'<div style=\\"font-size:1.8rem;display:flex;align-items:center;justify-content:center;height:100%\\"></div>'}</div>
              <div style="flex:1;min-width:0">
                <strong style="font-size:.875rem">\${p.name}</strong>
                <div style="color:#8c8f94;font-size:.75rem">v\${p.version||''} ·  : \${installs}</div>
              </div>
            </div>
            <p style="margin:0;font-size:.8rem;color:#50575e;line-height:1.5;flex:1">\${(p.short_description||'').replace(/<[^>]+>/g,'').slice(0,120)}…</p>
            <div style="display:flex;flex-wrap:wrap;gap:4px">
              \${tags.map(t=>'<span style="background:#f0f0f1;color:#50575e;font-size:.7rem;padding:2px 7px;border-radius:20px">'+t+'</span>').join('')}
            </div>
            <div style="display:flex;align-items:center;gap:6px">
              <div style="flex:1;font-size:.75rem;color:#f0ad00">\${''.repeat(stars)+(''.repeat(5-stars))} <span style="color:#8c8f94">\${((p.rating||0)/20).toFixed(1)}</span></div>
              <button onclick="installPlugin('\${p.slug}','\${(p.name||'').replace(/'/g,'')}',this)" style="padding:6px 14px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600"> </button>
              <button onclick="window.open('https://wordpress.org/plugins/\${p.slug}/','_blank')" style="padding:6px 10px;background:#f6f7f7;border:1px solid #c3c4c7;border-radius:4px;cursor:pointer;font-size:.8rem"></button>
            </div>
          </div>\`;
        }).join('');
        bar.textContent = \`WordPress.org "\${q}" : \${plugins.length} \`;
      } else {
        title.textContent='  ';
        grid.innerHTML='<p style="color:#8c8f94;grid-column:1/-1">  .</p>';
        bar.textContent='WordPress.org   .';
      }
    }
  } catch(e) {
    loading.style.display='none';
    bar.textContent='WordPress.org API  : ' + e.message;
  }
}

async function filterPlugins(type) {
  document.querySelectorAll('.plugin-tab').forEach(b=>{
    b.style.background='#f6f7f7'; b.style.color='#1e1e1e'; b.style.borderColor='#c3c4c7';
  });
  const active = document.getElementById('tab-'+type);
  active.style.background='#2271b1'; active.style.color='#fff'; active.style.borderColor='#2271b1';
  //   WordPress.org API 
  const map = {featured:'browse=featured', popular:'browse=popular', new:'browse=new'};
  const bar = document.getElementById('search-results-bar');
  const section = document.getElementById('wp-org-plugin-results');
  const grid = document.getElementById('wp-org-plugin-grid');
  const title = document.getElementById('wp-org-results-title');
  bar.style.display='block'; bar.textContent='WordPress.org  …';
  document.getElementById('plugin-search').value='';
  document.querySelectorAll('.plugin-install-card').forEach(c=>c.style.display='');
  try {
    const url='https://api.wordpress.org/plugins/info/1.2/?action=query_plugins&request['+map[type]+']&request[per_page]=12&request[fields][short_description]=1&request[fields][icons]=1&request[fields][downloaded]=1&request[fields][rating]=1&request[fields][active_installs]=1&request[fields][tags]=1&request[fields][version]=1';
    const r = await fetch(url);
    if (r.ok) {
      const data = await r.json();
      const plugins = data.plugins||[];
      title.textContent = {featured:' ',popular:' ',new:' '}[type];
      grid.innerHTML = plugins.map(p => {
        const icon = (p.icons&&(p.icons['1x']||p.icons.default))||'';
        const stars = Math.round((p.rating||0)/20);
        const installs = p.active_installs>=1000000?Math.floor(p.active_installs/1000000)+'M+':p.active_installs>=1000?Math.floor(p.active_installs/1000)+'K+':p.active_installs+'';
        return \`<div style="border:1px solid #c3c4c7;border-radius:6px;background:#fff;padding:16px;display:flex;flex-direction:column;gap:10px">
          <div style="display:flex;align-items:flex-start;gap:12px">
            <div style="width:48px;height:48px;border-radius:8px;overflow:hidden;background:#f6f7f7;flex-shrink:0">\${icon?'<img src="'+icon+'" style="width:100%;height:100%;object-fit:cover">':''}</div>
            <div><strong style="font-size:.875rem">\${p.name}</strong><div style="color:#8c8f94;font-size:.75rem">v\${p.version||''} · : \${installs}</div></div>
          </div>
          <p style="margin:0;font-size:.8rem;color:#50575e;line-height:1.5;flex:1">\${(p.short_description||'').replace(/<[^>]+>/g,'').slice(0,120)}…</p>
          <div style="display:flex;align-items:center;gap:6px">
            <div style="flex:1;font-size:.75rem;color:#f0ad00">\${''.repeat(stars)+(''.repeat(5-stars))}</div>
            <button onclick="installPlugin('\${p.slug}','\${(p.name||'').replace(/'/g,'')}',this)" style="padding:6px 14px;background:#2271b1;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600"> </button>
          </div>
        </div>\`;
      }).join('');
      section.style.display='block';
      bar.textContent = \`\${title.textContent}: \${plugins.length}\`;
    }
  } catch(e) { bar.textContent=' : '+e.message; }
}

async function installPlugin(slug, name, btn) {
  btn.textContent=' …'; btn.disabled=true; btn.style.background='#72aee6';
  try {
    const r = await fetch('/wp-json/cloudpress/v1/plugins/install', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({slug, name})
    });
    const d = r.ok ? await r.json() : {success:false, message:' '};
    if (d.success) {
      btn.textContent=''; btn.style.background='#00a32a'; btn.disabled=false;
      btn.setAttribute('onclick', \`activatePlugin('\${slug}','\${name}',this)\`);
      //    
      const card = btn.closest('[data-slug],[style*="border-radius:6px"]');
      if (card) {
        const nameEl = card.querySelector('strong');
        if (nameEl && !nameEl.nextElementSibling?.textContent?.includes('')) {
          const badge = document.createElement('span');
          badge.style.cssText='background:#00a32a;color:#fff;font-size:.65rem;padding:2px 6px;border-radius:20px;margin-left:6px';
          badge.textContent='';
          nameEl.after(badge);
        }
      }
    } else {
      btn.textContent=' '; btn.style.background='#d63638'; btn.disabled=false;
      setTimeout(()=>{ btn.textContent=' '; btn.style.background='#2271b1'; }, 2000);
    }
  } catch(e) { btn.textContent=': '+e.message.slice(0,20); btn.style.background='#d63638'; btn.disabled=false; }
}

async function activatePlugin(slug, name, btn) {
  btn.textContent=' …'; btn.disabled=true;
  try {
    const r = await fetch('/wp-json/cloudpress/v1/plugins/activate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({slug, name})
    });
    const d = r.ok ? await r.json() : {success:false};
    if (d.success) {
      btn.textContent=' '; btn.style.background='#00a32a';
      setTimeout(()=>{ window.location.href='/wp-admin/plugins.php'; }, 1000);
    } else {
      btn.textContent=' '; btn.disabled=false;
      alert(' : ' + (d.message||'   '));
    }
  } catch(e) { btn.textContent=''; btn.disabled=false; }
}

//  ZIP   
let _zipFile = null;

function toggleZipUpload() {
  const panel = document.getElementById('zip-upload-panel');
  const tab = document.getElementById('tab-zip');
  const isOpen = panel.style.display !== 'none';
  panel.style.display = isOpen ? 'none' : 'block';
  tab.style.background = isOpen ? '#f6f7f7' : '#2271b1';
  tab.style.color = isOpen ? '#1e1e1e' : '#fff';
  tab.style.borderColor = isOpen ? '#c3c4c7' : '#2271b1';
  if (!isOpen) { _zipFile = null; document.getElementById('zip-result').style.display='none'; }
}

function handleZipDrop(e) {
  e.preventDefault();
  document.getElementById('zip-drop-zone').style.borderColor='#c3c4c7';
  const file = e.dataTransfer.files[0];
  if (file) handleZipFile(file);
}

function handleZipFile(file) {
  if (!file) return;
  if (!file.name.endsWith('.zip')) {
    alert('ZIP    .');
    return;
  }
  if (file.size > 32 * 1024 * 1024) {
    alert('  32MB .');
    return;
  }
  _zipFile = file;
  const infoEl = document.getElementById('zip-info');
  infoEl.style.display='block';
  infoEl.innerHTML = \`<strong> \${file.name}</strong> <span style="color:#8c8f94;font-size:.8rem">(\${(file.size/1024/1024).toFixed(1)} MB)</span>\`;
  const btn = document.getElementById('btn-zip-install');
  btn.disabled=false; btn.style.opacity='1';
  document.getElementById('zip-result').style.display='none';
}

async function installZipPlugin() {
  if (!_zipFile) return;
  const btn = document.getElementById('btn-zip-install');
  const progress = document.getElementById('zip-progress');
  const progressBar = document.getElementById('zip-progress-bar');
  const progressText = document.getElementById('zip-progress-text');
  const result = document.getElementById('zip-result');

  btn.disabled=true; btn.style.opacity='.5';
  progress.style.display='block'; result.style.display='none';

  // ZIP  base64 
  progressBar.style.width='20%'; progressText.textContent='  ...';
  try {
    const arrayBuffer = await _zipFile.arrayBuffer();
    const uint8 = new Uint8Array(arrayBuffer);
    let binary=''; uint8.forEach(b=>binary+=String.fromCharCode(b));
    const base64 = btoa(binary);
    const pluginName = _zipFile.name.replace(/\\.zip$/i,'');
    const slug = pluginName.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');

    progressBar.style.width='60%'; progressText.textContent='  ...';

    const r = await fetch('/wp-json/cloudpress/v1/plugins/install-zip', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ slug, name: pluginName, zip_base64: base64, file_name: _zipFile.name })
    });
    const d = r.ok ? await r.json() : { success:false, message:' ' };

    progressBar.style.width='100%';
    progress.style.display='none';

    if (d.success) {
      result.style.cssText='display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px';
      result.innerHTML = \` <strong>\${d.plugin?.name||pluginName}</strong>  ! <button onclick="activateAfterZip('\${slug}','\${d.plugin?.name||pluginName}')" style="margin-left:10px;padding:4px 10px;background:#00a32a;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:.8rem"></button>\`;
      _zipFile=null;
    } else {
      result.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
      result.textContent = '  : ' + (d.message||'   ');
      btn.disabled=false; btn.style.opacity='1';
    }
  } catch(e) {
    progress.style.display='none';
    result.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
    result.textContent=': ' + e.message;
    btn.disabled=false; btn.style.opacity='1';
  }
}

async function activateAfterZip(slug, name) {
  const r = await fetch('/wp-json/cloudpress/v1/plugins/activate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug, name})
  });
  const d = r.ok ? await r.json() : {success:false};
  if (d.success) { alert(name + ' !'); window.location.href='/wp-admin/plugins.php'; }
  else { alert(' : ' + (d.message||'')); }
}`;

    } else {
      //     
      bodyHtml = `
<div id="plugin-msg" style="display:none;padding:10px 14px;border-radius:4px;margin-bottom:12px"></div>
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
  <div style="display:flex;align-items:center;gap:8px">
    <h2 style="margin:0;font-size:1.1rem"></h2>
    <span id="plugin-count" style="background:#f0f0f1;color:#50575e;font-size:.75rem;padding:2px 8px;border-radius:20px"> …</span>
  </div>
  <div style="display:flex;gap:8px">
    <input type="text" id="plugin-filter" placeholder=" …" oninput="filterList(this.value)"
      style="padding:6px 10px;border:1px solid #8c8f94;border-radius:4px;font-size:.8rem;width:200px">
    <a href="/wp-admin/plugin-install.php" class="btn-wp">  </a>
  </div>
</div>
<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
  <thead>
    <tr style="background:#f6f7f7;border-bottom:1px solid #c3c4c7">
      <th style="padding:8px 12px;text-align:left;font-size:.875rem"></th>
      <th style="padding:8px 12px;text-align:left;font-size:.875rem;width:80px"></th>
      <th style="padding:8px 12px;text-align:left;font-size:.875rem;width:90px"></th>
      <th style="padding:8px 12px;text-align:left;font-size:.875rem;width:200px"></th>
    </tr>
  </thead>
  <tbody id="plugins-list">
    <tr><td colspan="4" style="padding:20px;text-align:center;color:#8c8f94">   …</td></tr>
  </tbody>
</table>`;

      inlineScript = `
(async function() {
  const list = document.getElementById('plugins-list');
  const countEl = document.getElementById('plugin-count');
  try {
    const r = await fetch('/wp-json/cloudpress/v1/plugins', {headers:{'Accept':'application/json'}});
    const plugins = r.ok ? await r.json() : [];
    if (!plugins.length) {
      list.innerHTML='<tr><td colspan="4" style="padding:20px;text-align:center;color:#8c8f94">  . <a href="/wp-admin/plugin-install.php">  </a></td></tr>';
      countEl.textContent = '0';
      return;
    }
    countEl.textContent = plugins.length + '';
    renderPlugins(plugins);
  } catch(e) {
    list.innerHTML = '<tr><td colspan="4" style="padding:20px;text-align:center;color:#d63638"> : '+e.message+'</td></tr>';
  }
})();

function renderPlugins(plugins) {
  const list = document.getElementById('plugins-list');
  list.innerHTML = plugins.map(p => \`
    <tr id="row-\${p.slug}" style="border-top:1px solid #f0f0f1;\${p.active?'background:#f0f7e6':''}">
      <td style="padding:12px">
        <div style="display:flex;align-items:flex-start;gap:10px">
          \${p.icon?'<img src="'+p.icon+'" style="width:36px;height:36px;border-radius:6px;flex-shrink:0">':'<div style=\\"width:36px;height:36px;border-radius:6px;background:#f0f0f1;display:flex;align-items:center;justify-content:center;font-size:1.2rem;flex-shrink:0\\"></div>'}
          <div>
            <strong style="font-size:.9rem">\${p.name}</strong>
            <p style="margin:3px 0 0;font-size:.8rem;color:#50575e">\${p.description||''}</p>
            \${p.author?'<p style="margin:3px 0 0;font-size:.75rem;color:#8c8f94">: '+p.author+'</p>':''}
          </div>
        </div>
      </td>
      <td style="padding:12px;font-size:.8rem;color:#50575e;vertical-align:top">v\${p.version||'-'}</td>
      <td style="padding:12px;vertical-align:top">
        <span style="font-size:.8rem;font-weight:600;\${p.active?'color:#00a32a':'color:#8c8f94'}">\${p.active?' ':' '}</span>
      </td>
      <td style="padding:12px;vertical-align:top">
        <div style="display:flex;flex-wrap:wrap;gap:4px;font-size:.8rem">
          \${p.active
            ? '<button onclick="deactivatePlugin(\''+p.slug+'\',\''+p.name.replace(/'/g,'')+'\',this)" style="padding:4px 10px;background:#fff;border:1px solid #c3c4c7;border-radius:3px;cursor:pointer;font-size:.8rem"></button>'
            : '<button onclick="activatePlugin(\''+p.slug+'\',\''+p.name.replace(/'/g,'')+'\',this)" style="padding:4px 10px;background:#00a32a;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:.8rem;font-weight:600"></button>'
          }
          \${p.settings_url?'<a href="'+p.settings_url+'" style="padding:4px 10px;background:#f6f7f7;border:1px solid #c3c4c7;border-radius:3px;font-size:.8rem;text-decoration:none;color:#1e1e1e"></a>':''}
          \${!p.active?'<button onclick="deletePlugin(\''+p.slug+'\',\''+p.name.replace(/'/g,'')+'\',this)" style="padding:4px 10px;background:#fff;border:1px solid #d63638;color:#d63638;border-radius:3px;cursor:pointer;font-size:.8rem"></button>':''}
        </div>
      </td>
    </tr>\`).join('');
  window._pluginData = plugins;
}

function filterList(q) {
  const rows = document.querySelectorAll('#plugins-list tr[id]');
  const lq = q.toLowerCase();
  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(lq) ? '' : 'none';
  });
}

async function activatePlugin(slug, name, btn) {
  btn.textContent=' …'; btn.disabled=true;
  const r = await fetch('/wp-json/cloudpress/v1/plugins/activate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug, name})
  });
  const d = r.ok ? await r.json() : {success:false};
  showMsg(d.success ? ' ' + name + ' ' : ' : '+(d.message||''), d.success);
  if (d.success) location.reload();
  else { btn.textContent=''; btn.disabled=false; }
}

async function deactivatePlugin(slug, name, btn) {
  btn.textContent=' …'; btn.disabled=true;
  const r = await fetch('/wp-json/cloudpress/v1/plugins/deactivate', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug, name})
  });
  const d = r.ok ? await r.json() : {success:false};
  showMsg(d.success ? ' ' + name + ' ' : '', d.success);
  if (d.success) location.reload();
  else { btn.textContent=''; btn.disabled=false; }
}

async function deletePlugin(slug, name, btn) {
  if (!confirm(name + '  ?\\n    .')) return;
  btn.textContent=' …'; btn.disabled=true;
  const r = await fetch('/wp-json/cloudpress/v1/plugins/delete', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({slug})
  });
  const d = r.ok ? await r.json() : {success:false};
  if (d.success) {
    document.getElementById('row-'+slug)?.remove();
    showMsg(' ' + name + ' ', true);
  } else { btn.textContent=''; btn.disabled=false; showMsg(' ', false); }
}

function showMsg(text, ok) {
  const el = document.getElementById('plugin-msg');
  el.style.cssText = ok
    ? 'display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px;margin-bottom:12px'
    : 'display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px;margin-bottom:12px';
  el.textContent = text;
  setTimeout(()=>el.style.display='none', 4000);
}`;
    }


  } else if (page === 'options-general' || page === 'options') {
    pageTitle = ' ';
    bodyHtml = `<div id="settings-msg" style="display:none;padding:10px 14px;margin-bottom:16px;border-radius:4px"></div>
    <table class="form-table" style="width:100%;border-collapse:collapse">` +
      [
        {label:' ',          name:'blogname',        type:'text',  placeholder:' WordPress '},
        {label:'',             name:'blogdescription', type:'text',  placeholder:'  '},
        {label:'WordPress  (URL)',name:'siteurl',         type:'url',   placeholder:'https://example.com'},
        {label:'  (URL)',    name:'home',            type:'url',   placeholder:'https://example.com'},
        {label:' ',        name:'admin_email',     type:'email', placeholder:'admin@example.com'},
      ].map(f =>
        `<tr style="border-bottom:1px solid #f0f0f1">
          <th style="padding:15px 10px;text-align:left;width:220px;font-size:.875rem;vertical-align:top">${f.label}</th>
          <td style="padding:15px 10px"><input type="${f.type}" id="opt-${f.name}" name="${f.name}" placeholder="${f.placeholder}" style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"></td>
        </tr>`
      ).join('') +
      `<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem"></th>
        <td style="padding:15px 10px"><select style="padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"><option selected> (ko_KR)</option><option>English (US)</option></select></td></tr>
      <tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem"></th>
        <td style="padding:15px 10px"><select style="padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem"><option selected>Asia/Seoul</option><option>UTC</option></select></td></tr>
      </table>
      <p style="margin-top:20px"><button type="button" onclick="saveSettings()" class="btn-wp"> </button></p>`;

    inlineScript = `(async function(){
try{
  var r=await fetch('/wp-json/wp/v2/settings',{headers:{'Accept':'application/json'}});
  var res=r.ok?await r.json():{};
  if(res.title)document.getElementById('opt-blogname').value=res.title;
  if(res.description)document.getElementById('opt-blogdescription').value=res.description;
  if(res.url){document.getElementById('opt-siteurl').value=res.url;document.getElementById('opt-home').value=res.url;}
  if(res.email)document.getElementById('opt-admin_email').value=res.email;
}catch(e){}
})();
async function saveSettings(){
  var data={};
  document.querySelectorAll('input[name]').forEach(function(el){if(el.value.trim())data[el.name]=el.value.trim();});
  var msg=document.getElementById('settings-msg');
  try{
    var r=await fetch('/wp-json/wp/v2/settings',{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify(data)});
    if(r.ok){
      msg.style.cssText='display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px';
      msg.textContent='  .';
    }else{
      msg.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
      msg.textContent=' .';
    }
  }catch(e){
    msg.style.cssText='display:block;background:#fff0f0;border:1px solid #d63638;color:#d63638;padding:10px 14px;border-radius:4px';
    msg.textContent=': '+e.message;
  }
}`;

  } else if (page === 'users') {
    pageTitle = '';
    bodyHtml = `<div class="tablenav top" style="margin-bottom:10px"><a href="/wp-admin/user-new.php" class="btn-wp">  </a></div>
    <table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <th style="padding:8px 10px;text-align:left"></th>
        <th style="padding:8px 10px;text-align:left"></th>
        <th style="padding:8px 10px;text-align:left"></th>
        <th style="padding:8px 10px;text-align:left"></th>
        <th style="padding:8px 10px;text-align:left"></th>
      </tr></thead>
      <tbody id="users-list"><tr><td colspan="5" style="padding:20px;text-align:center;color:#8c8f94"> ...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/users?per_page=20',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var users=r.ok?await r.json():[];
users=Array.isArray(users)?users:[];
var el=document.getElementById('users-list');
if(!users.length){el.innerHTML='<tr><td colspan="5" style="padding:20px;text-align:center;color:#8c8f94"> .</td></tr>';return;}
el.innerHTML=users.map(function(u){
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:8px 10px"><strong>'+(u.slug||u.name||'')+'</strong></td>'+
    '<td style="padding:8px 10px">'+(u.name||'—')+'</td>'+
    '<td style="padding:8px 10px">'+(u.email||'—')+'</td>'+
    '<td style="padding:8px 10px">'+(u.role||'')+'</td>'+
    '<td style="padding:8px 10px">'+(u.post_count||0)+'</td>'+
    '</tr>';
}).join('');
})();`;

  } else if (page === 'profile') {
    pageTitle = '';
    bodyHtml = `<div id="profile-msg" style="display:none;padding:10px 14px;margin-bottom:16px;border-radius:4px"></div>
    <table class="form-table" style="width:100%;border-collapse:collapse">` +
      [
        {label:'', id:'username',   val:session?.login||'admin', disabled:true,  type:'text'},
        {label:'',     id:'first_name', val:'', disabled:false, type:'text',  placeholder:''},
        {label:'',   id:'email',      val:'', disabled:false, type:'email', placeholder:'admin@example.com'},
      ].map(f =>
        `<tr style="border-bottom:1px solid #f0f0f1">
          <th style="padding:15px 10px;text-align:left;width:200px;font-size:.875rem">${f.label}</th>
          <td style="padding:15px 10px"><input type="${f.type}" id="${f.id}" value="${esc(f.val||'')}"${f.placeholder?` placeholder="${f.placeholder}"`:''}${f.disabled?' disabled':''} style="width:100%;max-width:400px;padding:6px 8px;border:1px solid ${f.disabled?'#dcdcde':'#8c8f94'};border-radius:4px;font-size:.875rem${f.disabled?';background:#f6f7f7;color:#8c8f94':''}"></td>
        </tr>`
      ).join('') +
      `<tr style="border-bottom:1px solid #f0f0f1"><th style="padding:15px 10px;font-size:.875rem"> </th>
        <td style="padding:15px 10px">
          <input type="password" id="new_pass1" placeholder=" " style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem;margin-bottom:8px"><br>
          <input type="password" id="new_pass2" placeholder=" " style="width:100%;max-width:400px;padding:6px 8px;border:1px solid #8c8f94;border-radius:4px;font-size:.875rem">
        </td></tr>
      </table>
      <p style="margin-top:20px"><button class="btn-wp" onclick="saveProfile()"> </button></p>`;
    inlineScript = `function saveProfile(){
  var p1=document.getElementById('new_pass1').value;
  var p2=document.getElementById('new_pass2').value;
  if(p1&&p1!==p2){alert('  .');return;}
  var msg=document.getElementById('profile-msg');
  msg.style.cssText='display:block;background:#edfaef;border:1px solid #00a32a;color:#1d7a35;padding:10px 14px;border-radius:4px';
  msg.textContent='  .';
}`;

  } else if (page === 'edit-comments') {
    pageTitle = '';
    bodyHtml = `<table class="wp-list-table" style="width:100%;border-collapse:collapse;border:1px solid #c3c4c7;background:#fff">
      <thead><tr style="background:#f6f7f7">
        <th style="padding:8px 10px;text-align:left"></th>
        <th style="padding:8px 10px;text-align:left"></th>
        <th style="padding:8px 10px;text-align:left;width:120px"></th>
      </tr></thead>
      <tbody id="comments-list"><tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94"> ...</td></tr></tbody>
    </table>`;
    inlineScript = `(async function(){
var r=await fetch('/wp-json/wp/v2/comments?per_page=20',{headers:{'Accept':'application/json'}}).catch(function(){return{ok:false};});
var list=r.ok?await r.json():[];
list=Array.isArray(list)?list:[];
var el=document.getElementById('comments-list');
if(!list.length){el.innerHTML='<tr><td colspan="3" style="padding:20px;text-align:center;color:#8c8f94"> .</td></tr>';return;}
el.innerHTML=list.map(function(c){
  var d=new Date(c.date).toLocaleDateString('ko-KR');
  var content=((c.content&&c.content.rendered)||'').replace(/<[^>]+>/g,'').slice(0,100);
  return '<tr style="border-top:1px solid #f0f0f1">'+
    '<td style="padding:10px;vertical-align:top"><strong>'+(c.author_name||'')+'</strong></td>'+
    '<td style="padding:10px;vertical-align:top;font-size:.875rem">'+content+'</td>'+
    '<td style="padding:10px;vertical-align:top;font-size:.8rem;color:#50575e">'+d+'</td>'+
    '</tr>';
}).join('');
})();`;

  } else if (page === 'options-permalink') {
    pageTitle = ' ';
    bodyHtml = `<p style="color:#50575e;margin-bottom:20px">WordPress      URL    .</p>` +
      [
        {label:'',        val:'',                               desc:'https://example.com/?p=123'},
        {label:' ', val:'/%year%/%monthnum%/%day%/%postname%/', desc:'https://example.com/2024/01/01/-/'},
        {label:' ',   val:'/%year%/%monthnum%/%postname%/',       desc:'https://example.com/2024/01/-/'},
        {label:'',        val:'/archives/%post_id%',                  desc:'https://example.com/archives/123'},
        {label:' ',     val:'/%postname%/',                         desc:'https://example.com/-/', checked:true},
      ].map(o =>
        `<label style="display:flex;align-items:flex-start;gap:10px;margin-bottom:14px;cursor:pointer">
          <input type="radio" name="permalink" value="${o.val}"${o.checked?' checked':''} style="margin-top:4px">
          <span><strong>${o.label}</strong>${o.desc?`<br><code style="font-size:.8rem;color:#50575e">${o.desc}</code>`:''}
          </span></label>`
      ).join('') +
      `<p style="margin-top:20px"><button type="button" class="btn-wp" onclick="alert('.')"> </button></p>`;

  } else {
    pageTitle = page.replace(/-/g,' ').replace(/\b\w/g, c => c.toUpperCase());
    bodyHtml = `<div style="background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:30px;text-align:center;color:#50575e">
      <p>  CloudPress Edge .</p>
    </div>`;
  }

  const menuActive = {
    dashboard: (page === 'index' || page === '' || page === 'dashboard'),
    posts:     (page === 'edit' && !isPage) || page === 'post-new' || page === 'post',
    media:     page === 'upload',
    pages:     page === 'edit' && isPage,
    comments:  page === 'edit-comments',
    themes:    page === 'themes' || page === 'theme-install',
    plugins:   page === 'plugins' || page === 'plugin-install',
    users:     page === 'users' || page === 'user-new' || page === 'profile',
    settings:  page === 'options-general' || page === 'options' || page === 'options-permalink',
  };

  // (menuItem function removed - now using inline SVG menu)

  return `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${pageTitle} &#8249; ${siteName} &#8212; WordPress</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f0f1;color:#1d2327;font-size:13px;line-height:1.4}
a{color:#2271b1;text-decoration:none}a:hover{color:#135e96}
#wpadminbar{position:fixed;top:0;left:0;right:0;height:32px;background:#1d2327;display:flex;align-items:center;padding:0 12px;z-index:9999;gap:0}
#wpadminbar .ab-item{color:#a7aaad;font-size:.8125rem;display:flex;align-items:center;gap:4px;text-decoration:none;padding:0 8px;height:32px;line-height:32px}
#wpadminbar .ab-item:hover{color:#fff;background:#3c434a}
#wpadminbar .ab-item svg{width:20px;height:20px;fill:#a7aaad;vertical-align:middle}
#wpadminbar .ab-item:hover svg{fill:#fff}
#wpadminbar .ab-label{font-size:.8125rem}
#wpadminbar .spacer{flex:1}
#adminmenuwrap{position:fixed;top:32px;left:0;bottom:0;width:160px;background:#1d2327;overflow-y:auto;z-index:100}
#adminmenu{list-style:none;margin:0;padding:0}
#adminmenu li>a{display:flex;align-items:center;gap:8px;padding:9px 10px;color:#a7aaad;font-size:.8125rem;text-decoration:none;transition:background .15s,color .1s}
#adminmenu li>a:hover,#adminmenu li.current>a{background:#2c3338;color:#fff}
#adminmenu li.current>a{border-left:3px solid #2271b1;padding-left:7px}
#adminmenu .menu-icon svg{width:16px;height:16px;fill:currentColor;flex-shrink:0}
#adminmenu .menu-sep{height:1px;background:#3c434a;margin:6px 0}
#wpcontent{margin-left:160px;margin-top:32px;min-height:calc(100vh - 32px)}
#wpbody-content{padding:20px 20px 40px}
.wrap{max-width:1200px}
h1.wp-heading-inline{font-size:1.4rem;font-weight:400;color:#1d2327;margin:0 0 20px;display:block}
.welcome-panel{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:23px;margin-bottom:20px}
.admin-widgets{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:20px;margin-top:16px}
.admin-widget{background:#fff;border:1px solid #c3c4c7;border-radius:4px;overflow:hidden}
.widget-title{background:#f6f7f7;border-bottom:1px solid #c3c4c7;padding:9px 12px;font-size:.875rem;font-weight:600;color:#1d2327}
.widget-body{padding:14px}
.btn-wp{display:inline-block;padding:6px 12px;background:#2271b1;color:#fff;border:1px solid #2271b1;border-radius:3px;font-size:.8125rem;cursor:pointer;text-decoration:none;line-height:1.4;transition:background .15s}
.btn-wp:hover{background:#135e96;border-color:#135e96;color:#fff;text-decoration:none}
.btn-wp.btn-secondary{background:#f6f7f7;color:#1d2327;border-color:#8c8f94}
.btn-wp.btn-secondary:hover{background:#dcdcde;color:#1d2327}
.wp-list-table th{font-weight:600;color:#1d2327}
.form-table th{font-weight:600;color:#1d2327;vertical-align:top}
.tablenav{display:flex;align-items:center;gap:10px}
@media(max-width:782px){
  #adminmenuwrap{width:36px;overflow:hidden}
  #adminmenuwrap:hover{width:160px}
  #adminmenu .menu-label{display:none}
  #adminmenuwrap:hover .menu-label{display:inline}
  #wpcontent{margin-left:36px}
}
</style>
</head>
<body class="wp-admin">
<div id="wpadminbar">
  <a class="ab-item" href="/wp-admin/" aria-label="WordPress">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 2C5.589 2 2 5.589 2 10s3.589 8 8 8 8-3.589 8-8-3.589-8-8-8zm-7 8c0-1.036.228-2.015.625-2.896l3.449 9.449C4.456 15.492 3 12.906 3 10zm7 7c-.698 0-1.372-.1-2.01-.281l2.133-6.198 2.186 5.99c.014.036.03.069.049.1A6.977 6.977 0 0110 17zm1.21-12.93c.529-.028.999-.084.999-.084.47-.056.414-.749-.056-.721 0 0-1.413.111-2.325.111-.857 0-2.298-.111-2.298-.111-.47-.028-.526.693-.055.721 0 0 .44.056.913.084l1.356 3.712-1.905 5.712-3.167-9.424c.528-.028.999-.084.999-.084.47-.056.414-.749-.056-.721 0 0-1.413.111-2.297.111.159-.244.331-.479.519-.702A7 7 0 0110 3a6.98 6.98 0 014.418 1.566c-.028 0-.055-.002-.084-.002-1.083 0-1.831.942-1.831 1.553 0 .664.52 1.027 1.014 1.495.471.44.999 1.027.999 1.943 0 .636-.246 1.404-.635 2.395l-.838 2.8-3.032-9.02-1.8.24zM14.577 6.58l1.95 5.641A6.995 6.995 0 0117 10c0-1.32-.365-2.554-.997-3.612l1.27-3.48-1.47.414-.226.618z"/></svg>
  </a>
  <a class="ab-item" href="/wp-admin/" title="${siteName} ">
    <span class="ab-label">${siteName}</span>
  </a>
  <a class="ab-item" href="/" title=" " target="_blank"> </a>
  <a class="ab-item" href="/wp-admin/post-new.php" title=" ">+  </a>
  <div class="spacer"></div>
  <a class="ab-item" href="/wp-admin/profile.php" title=" ">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 6c1.105 0 2 .895 2 2s-.895 2-2 2-2-.895-2-2 .895-2 2-2m0 9c-2.209 0-4-1.343-4-3s1.791-3 4-3 4 1.343 4 3-1.791 3-4 3m0-15C4.477 0 0 4.477 0 10s4.477 10 10 10 10-4.477 10-10S15.523 0 10 0z"/></svg>
    <span class="ab-label">${displayName}</span>
  </a>
  <a class="ab-item" href="/wp-login.php?action=logout" title="" style="color:#f86368"></a>
</div>
<div id="adminmenuwrap">
  <ul id="adminmenu">
    <li${menuActive.dashboard?' class="current"':''}><a href="/wp-admin/"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M3 3h7v7H3zm8 0h6v3h-6zm0 4h6v3h-6zm-8 4h7v7H3zm8 1h6v6h-6z"/></svg></span><span class="menu-label"></span></a></li>
    <li class="menu-sep"></li>
    <li${menuActive.posts?' class="current"':''}><a href="/wp-admin/edit.php"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M1 1h18v2H1zm0 4h18v2H1zm0 4h12v2H1zm0 4h18v2H1zm0 4h18v2H1z"/></svg></span><span class="menu-label"></span></a></li>
    <li${menuActive.media?' class="current"':''}><a href="/wp-admin/upload.php"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M18 12h-2.18c-.17.7-.44 1.35-.81 1.93l1.54 1.54-2.1 2.1-1.54-1.54c-.58.37-1.23.64-1.91.81V19H8v-2.16c-.68-.17-1.33-.44-1.91-.81l-1.54 1.54-2.12-2.12 1.54-1.54C3.6 13.35 3.33 12.7 3.16 12H1V9h2.16c.17-.7.44-1.35.81-1.93L2.43 5.53l2.1-2.1 1.54 1.54C6.65 4.6 7.3 4.33 8 4.16V2h3v2.16c.68.17 1.33.44 1.91.81l1.54-1.54 2.12 2.12-1.54 1.54c.37.58.64 1.23.81 1.91H18v3zm-8.5 1.5c1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3 1.34 3 3 3z"/></svg></span><span class="menu-label"></span></a></li>
    <li${menuActive.pages?' class="current"':''}><a href="/wp-admin/edit.php?post_type=page"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M13 2H3v16h14V6l-4-4zm2 14H5V4h7l3 3v9z"/></svg></span><span class="menu-label"></span></a></li>
    <li${menuActive.comments?' class="current"':''}><a href="/wp-admin/edit-comments.php"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M18 2H2v14h3v3l4-3h9V2zM5 9h10v2H5V9zm0-3h10v2H5V6zm7 6H5v2h7v-2z"/></svg></span><span class="menu-label"></span></a></li>
    <li class="menu-sep"></li>
    <li${menuActive.themes?' class="current"':''}><a href="/wp-admin/themes.php"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 0C4.477 0 0 4.477 0 10s4.477 10 10 10 10-4.477 10-10S15.523 0 10 0zm0 18C5.582 18 2 14.418 2 10S5.582 2 10 2s8 3.582 8 8-3.582 8-8 8zm1-13H9v6l5.25 3.15.75-1.23-4-2.37V5z"/></svg></span><span class="menu-label"></span></a></li>
    <li${menuActive.plugins?' class="current"':''}><a href="/wp-admin/plugins.php"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M18 8h-2V6c0-1.1-.9-2-2-2h-1V2h-2v2H9V2H7v2H6C4.9 4 4 4.9 4 6v2H2v2h2v1H2v2h2v1c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2v-1h2v-2h-2v-1h2V8zm-4 7H6V6h10v9z"/></svg></span><span class="menu-label"></span></a></li>
    <li${menuActive.users?' class="current"':''}><a href="/wp-admin/users.php"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 1C5.03 1 1 5.03 1 10s4.03 9 9 9 9-4.03 9-9-4.03-9-9-9zm0 4a3 3 0 110 6 3 3 0 010-6zm0 12.9c-2.57 0-4.84-1.2-6.32-3.07.23-.84.69-1.37 1.33-1.62.65-.26 1.42-.39 1.99-.39h6c.57 0 1.34.13 1.99.39.64.25 1.1.78 1.33 1.62A7.957 7.957 0 0110 17.9z"/></svg></span><span class="menu-label"></span></a></li>
    <li class="menu-sep"></li>
    <li${menuActive.settings?' class="current"':''}><a href="/wp-admin/options-general.php"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 1C4.477 1 0 5.477 0 11s4.477 10 10 10 10-4.477 10-10S15.523 1 10 1zm0 18C5.582 19 2 15.418 2 11S5.582 3 10 3s8 3.582 8 8-3.582 8-8 8zm1-13H9v6l5.25 3.15.75-1.23-4-2.37V6z"/></svg></span><span class="menu-label"></span></a></li>
    <li><a href="/" target="_blank"><span class="menu-icon"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M10 1C4.477 1 0 5.477 0 11s4.477 10 10 10 10-4.477 10-10S15.523 1 10 1zm-1 14.414V13H5.586L10 8.586 14.414 13H11v2.414L10 16.414l-1-1zm8-4.414A8 8 0 0110 19a8 8 0 01-8-8 8 8 0 018-8 8 8 0 018 8z"/></svg></span><span class="menu-label"> </span></a></li>
  </ul>
</div>
<div id="wpcontent">
  <div id="wpbody-content">
    <div class="wrap">
      <h1 class="wp-heading-inline">${pageTitle}</h1>
      ${bodyHtml}
      ${inlineScript ? `<script>${inlineScript}<\/script>` : ''}
    </div>
  </div>
</div>
</body>
</html>`;
}

//  REST API 
async function handleWPRestAPI(env, request, url, siteInfo) {
  const path = url.pathname.replace('/wp-json', '');
  const method = request.method;

  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WP-Nonce',
    'Content-Type': 'application/json; charset=utf-8',
  };

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });

  const j = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: corsHeaders });

  try {
    // GET /wp/v2/posts
    if (path.match(/^\/wp\/v2\/posts\/?$/) && method === 'GET') {
      const perPage = Math.min(parseInt(url.searchParams.get('per_page') || '10', 10), 100);
      const page    = parseInt(url.searchParams.get('page') || '1', 10);
      const offset  = (page - 1) * perPage;
      const search  = url.searchParams.get('search') || '';
      const fields  = url.searchParams.get('_fields') || '';
      const statusParam = url.searchParams.get('status') || 'publish';

      //    
      const allowedStatuses = ['publish','draft','future','private','pending','trash'];
      const requestedStatuses = statusParam.split(',').map(s => s.trim()).filter(s => allowedStatuses.includes(s));
      const statuses = requestedStatuses.length ? requestedStatuses : ['publish'];
      const statusPlaceholders = statuses.map(() => '?').join(',');

      let sql = `SELECT * FROM wp_posts WHERE post_type = 'post' AND post_status IN (${statusPlaceholders})`;
      const binds = [...statuses];
      if (search) { sql += ` AND (post_title LIKE ? OR post_content LIKE ?)`; binds.push(`%${search}%`, `%${search}%`); }
      sql += ` ORDER BY post_date DESC LIMIT ? OFFSET ?`;
      binds.push(perPage, offset);

      const res = await env.DB.prepare(sql).bind(...binds).all();
      const posts = (res.results || []).map(wpPostToJSON);
      const countSql = `SELECT COUNT(*) as c FROM wp_posts WHERE post_type='post' AND post_status IN (${statusPlaceholders})`;
      const countRes = await env.DB.prepare(countSql).bind(...statuses).first();
      const total = countRes?.c || 0;

      return new Response(JSON.stringify(posts), {
        status: 200,
        headers: { ...corsHeaders, 'X-WP-Total': String(total), 'X-WP-TotalPages': String(Math.ceil(total / perPage)) },
      });
    }

    // POST /wp/v2/posts
    if (path.match(/^\/wp\/v2\/posts\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const title   = String(body.title?.raw || body.title || '');
      const content = String(body.content?.raw || body.content || '');
      const excerpt = String(body.excerpt?.raw || body.excerpt || '');
      const status  = ['publish','draft','private','future','pending'].includes(body.status) ? body.status : 'publish';
      const slug    = body.slug || title.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-|-$/g, '') || `post-${Date.now()}`;
      const now     = new Date().toISOString().replace('T', ' ').slice(0, 19);
      // : date/date_gmt  
      let postDate = now, postDateGmt = now;
      if (body.date) { try { postDate = new Date(body.date).toISOString().replace('T',' ').slice(0,19); postDateGmt = postDate; } catch {} }
      if (body.date_gmt) { try { postDateGmt = new Date(body.date_gmt).toISOString().replace('T',' ').slice(0,19); } catch {} }
      if (!title) return j({ code: 'rest_title_required', message: ' .' }, 400);
      try {
        const result = await env.DB.prepare(
          `INSERT INTO wp_posts (post_title, post_content, post_excerpt, post_status, post_type, post_name, post_date, post_date_gmt, post_modified, post_modified_gmt, post_author, comment_status, ping_status, guid)
           VALUES (?, ?, ?, ?, 'post', ?, ?, ?, ?, ?, 1, 'open', 'open', ?)`
        ).bind(title, content, excerpt, status, slug, postDate, postDateGmt, now, now, slug).run();
        const newId = result.meta?.last_row_id || result.lastRowId || Date.now();
        const newPost = await env.DB.prepare(`SELECT * FROM wp_posts WHERE ID = ? LIMIT 1`).bind(newId).first().catch(() => null);
        //  
        if (body.categories && Array.isArray(body.categories) && body.categories.length && newId) {
          for (const catId of body.categories) {
            const tt = await env.DB.prepare(`SELECT term_taxonomy_id FROM wp_term_taxonomy WHERE term_id = ? AND taxonomy = 'category' LIMIT 1`).bind(catId).first().catch(() => null);
            if (tt) {
              await env.DB.prepare(`INSERT OR IGNORE INTO wp_term_relationships (object_id, term_taxonomy_id) VALUES (?, ?)`).bind(newId, tt.term_taxonomy_id).run().catch(() => {});
            }
          }
        }
        return j(wpPostToJSON(newPost || { ID: newId, post_title: title, post_content: content, post_status: status, post_name: slug, post_date: postDate }), 201);
      } catch (e) {
        return j({ code: 'rest_db_error', message: ' : ' + e.message }, 500);
      }
    }

    // PATCH /wp/v2/posts/:id
    if (path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/) && (method === 'PUT' || method === 'PATCH')) {
      const postId = parseInt(path.match(/\/posts\/(\d+)/)[1], 10);
      const body = await request.json().catch(() => ({}));
      const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
      const fields = [], binds = [];
      if (body.title   !== undefined) { fields.push('post_title = ?');   binds.push(String(body.title?.raw || body.title || '')); }
      if (body.content !== undefined) { fields.push('post_content = ?'); binds.push(String(body.content?.raw || body.content || '')); }
      if (body.excerpt !== undefined) { fields.push('post_excerpt = ?'); binds.push(String(body.excerpt?.raw || body.excerpt || '')); }
      if (body.status  !== undefined) { fields.push('post_status = ?');  binds.push(body.status); }
      if (body.slug    !== undefined) { fields.push('post_name = ?');    binds.push(body.slug); }
      if (body.date    !== undefined) { try { const d=new Date(body.date).toISOString().replace('T',' ').slice(0,19); fields.push('post_date = ?','post_date_gmt = ?'); binds.push(d,d); } catch {} }
      if (!fields.length) return j({ code: 'rest_no_fields', message: '  .' }, 400);
      fields.push('post_modified = ?', 'post_modified_gmt = ?');
      binds.push(now, now, postId);
      await env.DB.prepare(`UPDATE wp_posts SET ${fields.join(', ')} WHERE ID = ?`).bind(...binds).run();
      const updated = await env.DB.prepare(`SELECT * FROM wp_posts WHERE ID = ? LIMIT 1`).bind(postId).first();
      return j(wpPostToJSON(updated));
    }

    // DELETE /wp/v2/posts/:id
    if (path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/) && method === 'DELETE') {
      const postId = parseInt(path.match(/\/posts\/(\d+)/)[1], 10);
      await env.DB.prepare(`UPDATE wp_posts SET post_status = 'trash' WHERE ID = ?`).bind(postId).run();
      return j({ deleted: true, id: postId });
    }

    // GET /wp/v2/posts/:id
    const postMatch = path.match(/^\/wp\/v2\/posts\/(\d+)\/?$/);
    if (postMatch && method === 'GET') {
      const post = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE ID = ? AND post_status IN ('publish','draft') LIMIT 1`
      ).bind(parseInt(postMatch[1], 10)).first();
      if (!post) return j({ code: 'rest_post_invalid_id', message: '   ID.' }, 404);
      return j(wpPostToJSON(post));
    }

    // GET /wp/v2/pages
    if (path.match(/^\/wp\/v2\/pages\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT * FROM wp_posts WHERE post_type = 'page' AND post_status = 'publish' ORDER BY menu_order ASC, post_date DESC LIMIT 100`
      ).all();
      return j((res.results || []).map(wpPostToJSON));
    }

    // GET /wp/v2/categories
    if (path.match(/^\/wp\/v2\/categories\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT t.term_id as id, t.name, t.slug, tt.description, tt.count, tt.parent FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id WHERE tt.taxonomy = 'category' ORDER BY t.name ASC`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/tags
    if (path.match(/^\/wp\/v2\/tags\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT t.term_id as id, t.name, t.slug, tt.description, tt.count FROM wp_terms t JOIN wp_term_taxonomy tt ON tt.term_id = t.term_id WHERE tt.taxonomy = 'post_tag' ORDER BY tt.count DESC LIMIT 100`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/users
    if (path.match(/^\/wp\/v2\/users\/?$/) && method === 'GET') {
      const res = await env.DB.prepare(
        `SELECT ID as id, display_name as name, user_login as slug, user_url as url FROM wp_users LIMIT 20`
      ).all();
      return j(res.results || []);
    }

    // GET /wp/v2/media
    if (path.match(/^\/wp\/v2\/media\/?$/) && method === 'GET') {
      try {
        const res = await env.DB.prepare(
          `SELECT media_id as id, file_name as slug, alt_text, caption, mime_type, file_size, file_path as source_url FROM wp_media ORDER BY upload_date DESC LIMIT 30`
        ).all();
        return j((res.results || []).map(m => ({
          ...m, title: { rendered: m.slug || '' }, guid: { rendered: m.source_url || '' },
        })));
      } catch { return j([]); }
    }

    // GET /wp/v2/comments
    if (path.match(/^\/wp\/v2\/comments\/?$/) && method === 'GET') {
      try {
        const perPage = parseInt(url.searchParams.get('per_page') || '20', 10);
        const res = await env.DB.prepare(
          `SELECT comment_ID as id, comment_author as author_name, comment_content as content, comment_date as date, comment_post_ID as post FROM wp_comments WHERE comment_approved = '1' ORDER BY comment_date DESC LIMIT ?`
        ).bind(perPage).all();
        const total = await env.DB.prepare(`SELECT COUNT(*) as c FROM wp_comments WHERE comment_approved='1'`).first();
        return new Response(JSON.stringify((res.results || []).map(c => ({ ...c, content: { rendered: c.content || '' } }))), {
          status: 200,
          headers: { ...corsHeaders, 'X-WP-Total': String(total?.c || 0) },
        });
      } catch { return j([]); }
    }

    // GET /wp/v2/settings
    if (path.match(/^\/wp\/v2\/settings\/?$/) && method === 'GET') {
      const opts = await getWPOptions(env, siteInfo.site_prefix, ['blogname','blogdescription','siteurl','admin_email','timezone_string','date_format','posts_per_page']);
      return j({
        title: opts.blogname || '',
        description: opts.blogdescription || '',
        url: opts.siteurl || '',
        email: opts.admin_email || '',
        timezone: opts.timezone_string || 'Asia/Seoul',
        date_format: opts.date_format || 'Y n j',
        posts_per_page: parseInt(opts.posts_per_page || '10', 10),
      });
    }

    // POST /wp/v2/settings
    if (path.match(/^\/wp\/v2\/settings\/?$/) && method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const map = { title:'blogname', description:'blogdescription', email:'admin_email', timezone:'timezone_string', date_format:'date_format', posts_per_page:'posts_per_page' };
      const updated = {};
      for (const [bodyKey, optKey] of Object.entries(map)) {
        if (body[bodyKey] !== undefined) {
          const val = String(body[bodyKey]);
          try {
            await env.DB.prepare(
              `INSERT INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'yes') ON CONFLICT(option_name) DO UPDATE SET option_value = excluded.option_value`
            ).bind(optKey, val).run();
            updated[bodyKey] = val;
          } catch {}
        }
      }
      return j({ ...updated, ok: true });
    }

    //  CloudPress v1 API 

    // GET /cloudpress/v1/plugins —   
    if (path === '/cloudpress/v1/plugins' && method === 'GET') {
      try {
        const res = await env.DB.prepare(
          `SELECT option_value FROM wp_options WHERE option_name = 'active_plugins' LIMIT 1`
        ).first();
        const allPluginsRes = await env.DB.prepare(
          `SELECT option_name, option_value FROM wp_options WHERE option_name LIKE 'cp_plugin_%'`
        ).all();
        const activePlugins = res?.option_value ? JSON.parse(res.option_value) : [];
        const pluginMeta = {};
        for (const row of (allPluginsRes.results || [])) {
          try { pluginMeta[row.option_name] = JSON.parse(row.option_value); } catch {}
        }
        // DB    (   )
        const dbPlugins = Object.entries(pluginMeta).map(([k, v]) => ({
          slug: k.replace('cp_plugin_', ''),
          ...v,
        }));
        const result = dbPlugins.map(p => ({
          ...p,
          active: activePlugins.includes(p.slug) || activePlugins.includes(p.slug + '/index.php'),
        }));
        return j(result);
      } catch(e) {
        return j([]);
      }
    }

    // POST /cloudpress/v1/plugins/install
    if (path === '/cloudpress/v1/plugins/install' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug, name } = body;
      if (!slug) return j({ success: false, message: 'slug ' }, 400);
      try {
        // WordPress.org API   
        let pluginInfo = { slug, name: name || slug, version: 'latest', description: '' };
        try {
          const wpRes = await fetch(
            `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(slug)}&request[fields][short_description]=1&request[fields][versions]=0&request[fields][icons]=1`,
            { headers: { 'User-Agent': 'CloudPress/20' } }
          );
          if (wpRes.ok) {
            const info = await wpRes.json();
            if (info && info.slug) {
              pluginInfo = {
                slug: info.slug,
                name: info.name || name || slug,
                version: info.version || 'latest',
                description: (info.short_description || '').replace(/<[^>]+>/g, '').slice(0, 200),
                author: (info.author || '').replace(/<[^>]+>/g, ''),
                icon: info.icons?.['1x'] || info.icons?.default || '',
                download_link: info.download_link || '',
                installed_at: new Date().toISOString(),
              };
            }
          }
        } catch {}
        // DB   
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'no')`
        ).bind(`cp_plugin_${slug}`, JSON.stringify(pluginInfo)).run();
        return j({ success: true, plugin: pluginInfo, message: `${pluginInfo.name} ` });
      } catch(e) {
        return j({ success: false, message: ' : ' + e.message }, 500);
      }
    }

    // POST /cloudpress/v1/plugins/activate
    if (path === '/cloudpress/v1/plugins/activate' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug } = body;
      if (!slug) return j({ success: false, message: 'slug ' }, 400);
      try {
        const res = await env.DB.prepare(
          `SELECT option_value FROM wp_options WHERE option_name = 'active_plugins' LIMIT 1`
        ).first();
        const active = res?.option_value ? JSON.parse(res.option_value) : [];
        if (!active.includes(slug)) active.push(slug);
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('active_plugins', ?, 'yes')`
        ).bind(JSON.stringify(active)).run();
        return j({ success: true, message: `${slug} `, active_plugins: active });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/plugins/deactivate
    if (path === '/cloudpress/v1/plugins/deactivate' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug } = body;
      if (!slug) return j({ success: false, message: 'slug ' }, 400);
      try {
        const res = await env.DB.prepare(
          `SELECT option_value FROM wp_options WHERE option_name = 'active_plugins' LIMIT 1`
        ).first();
        const active = (res?.option_value ? JSON.parse(res.option_value) : []).filter(s => s !== slug);
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('active_plugins', ?, 'yes')`
        ).bind(JSON.stringify(active)).run();
        return j({ success: true, message: `${slug} ` });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/plugins/delete
    if (path === '/cloudpress/v1/plugins/delete' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug } = body;
      if (!slug) return j({ success: false, message: 'slug ' }, 400);
      try {
        // active_plugins 
        const res = await env.DB.prepare(
          `SELECT option_value FROM wp_options WHERE option_name = 'active_plugins' LIMIT 1`
        ).first();
        const active = (res?.option_value ? JSON.parse(res.option_value) : []).filter(s => s !== slug);
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('active_plugins', ?, 'yes')`
        ).bind(JSON.stringify(active)).run();
        //   
        await env.DB.prepare(`DELETE FROM wp_options WHERE option_name = ?`).bind(`cp_plugin_${slug}`).run();
        return j({ success: true, message: `${slug} ` });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/plugins/install-zip — ZIP   
    if (path === '/cloudpress/v1/plugins/install-zip' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug, name, zip_base64, file_name } = body;
      if (!slug || !zip_base64) return j({ success: false, message: 'slug zip_base64 ' }, 400);
      try {
        // ZIP    
        const zipSize = Math.round(zip_base64.length * 0.75); // approximate decoded size
        const pluginInfo = {
          slug,
          name: name || slug,
          version: 'custom',
          description: 'ZIP   ',
          author: ' ',
          file_name: file_name || slug + '.zip',
          zip_size: zipSize,
          installed_at: new Date().toISOString(),
          install_method: 'zip',
        };
        // DB  (ZIP  ,    )
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'no')`
        ).bind(`cp_plugin_${slug}`, JSON.stringify(pluginInfo)).run();
        return j({ success: true, plugin: pluginInfo, message: `${pluginInfo.name}  (ZIP)` });
      } catch(e) {
        return j({ success: false, message: 'ZIP  : ' + e.message }, 500);
      }
    }

    // POST /cloudpress/v1/themes/install
    if (path === '/cloudpress/v1/themes/install' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug, name } = body;
      if (!slug) return j({ success: false, message: 'slug ' }, 400);
      try {
        let themeInfo = { slug, name: name || slug, version: 'latest' };
        try {
          const wpRes = await fetch(
            `https://api.wordpress.org/themes/info/1.1/?action=theme_information&request[slug]=${encodeURIComponent(slug)}&request[fields][description]=1&request[fields][screenshots]=1&request[fields][version]=1`,
            { headers: { 'User-Agent': 'CloudPress/20' } }
          );
          if (wpRes.ok) {
            const info = await wpRes.json();
            if (info && info.slug) {
              themeInfo = {
                slug: info.slug,
                name: info.name || name || slug,
                version: info.version || 'latest',
                description: (info.description || '').replace(/<[^>]+>/g, '').slice(0, 200),
                author: (info.author || '').replace(/<[^>]+>/g, ''),
                screenshot_url: info.screenshot_url || '',
                installed_at: new Date().toISOString(),
              };
            }
          }
        } catch {}
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'no')`
        ).bind(`cp_theme_${slug}`, JSON.stringify(themeInfo)).run();
        return j({ success: true, theme: themeInfo, message: `${themeInfo.name} ` });
      } catch(e) { return j({ success: false, message: '  : ' + e.message }, 500); }
    }

    // POST /cloudpress/v1/themes/activate
    if (path === '/cloudpress/v1/themes/activate' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug, name } = body;
      if (!slug) return j({ success: false, message: 'slug ' }, 400);
      try {
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('stylesheet', ?, 'yes')`
        ).bind(slug).run();
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES ('template', ?, 'yes')`
        ).bind(slug).run();
        return j({ success: true, message: `${name || slug}  `, active_theme: slug });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/themes/delete
    if (path === '/cloudpress/v1/themes/delete' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug } = body;
      if (!slug) return j({ success: false, message: 'slug ' }, 400);
      try {
        await env.DB.prepare(`DELETE FROM wp_options WHERE option_name = ?`).bind(`cp_theme_${slug}`).run();
        return j({ success: true, message: `${slug}  ` });
      } catch(e) { return j({ success: false, message: e.message }, 500); }
    }

    // POST /cloudpress/v1/themes/install-zip — ZIP   
    if (path === '/cloudpress/v1/themes/install-zip' && method === 'POST') {
      let body = {};
      try { body = await request.json(); } catch {}
      const { slug, name, zip_base64, file_name } = body;
      if (!slug || !zip_base64) return j({ success: false, message: 'slug zip_base64 ' }, 400);
      try {
        const themeInfo = {
          slug,
          name: name || slug,
          version: 'custom',
          description: 'ZIP   ',
          author: ' ',
          file_name: file_name || slug + '.zip',
          installed_at: new Date().toISOString(),
          install_method: 'zip',
        };
        await env.DB.prepare(
          `INSERT OR REPLACE INTO wp_options (option_name, option_value, autoload) VALUES (?, ?, 'no')`
        ).bind(`cp_theme_${slug}`, JSON.stringify(themeInfo)).run();
        return j({ success: true, theme: themeInfo, message: `${themeInfo.name}   (ZIP)` });
      } catch(e) {
        return j({ success: false, message: 'ZIP   : ' + e.message }, 500);
      }
    }

    return j({ code: 'rest_no_route', message: '  .', data: { status: 404 } }, 404);
  } catch (e) {
    console.error('[REST API] error:', e.message);
    return j({ code: 'rest_error', message: '  .' }, 500);
  }
}

function wpPostToJSON(p) {
  if (!p) return null;
  return {
    id: p.ID || p.id,
    date: p.post_date,
    date_gmt: p.post_date_gmt,
    modified: p.post_modified,
    slug: p.post_name,
    status: p.post_status,
    type: p.post_type,
    link: p.guid || `/?p=${p.ID||p.id}`,
    title: { rendered: p.post_title || '', raw: p.post_title || '' },
    content: { rendered: p.post_content || '', raw: p.post_content || '', protected: false },
    excerpt: { rendered: p.post_excerpt || '', raw: p.post_excerpt || '', protected: false },
    author: p.post_author || 1,
    comment_status: p.comment_status || 'open',
    comment_count: p.comment_count || 0,
    _links: {
      self: [{ href: `/wp-json/wp/v2/posts/${p.ID||p.id}` }],
      collection: [{ href: '/wp-json/wp/v2/posts' }],
    },
  };
}

async function handleRSSFeed(env, siteInfo, url) {
  const opts = await getWPOptions(env, siteInfo.site_prefix, ['blogname','blogdescription','siteurl']);
  const siteName = opts.blogname || siteInfo.name;
  const siteUrl  = `https://${url.hostname}`;
  let posts = [];
  try {
    const res = await env.DB.prepare(
      `SELECT ID, post_title, post_content, post_excerpt, post_date, post_name FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 10`
    ).all();
    posts = res.results || [];
  } catch {}
  const items = posts.map(p => {
    const link = `${siteUrl}/${p.post_name}/`;
    return `<item>
  <title><![CDATA[${p.post_title}]]></title>
  <link>${link}</link>
  <pubDate>${new Date(p.post_date).toUTCString()}</pubDate>
  <guid isPermaLink="true">${link}</guid>
  <description><![CDATA[${(p.post_excerpt || p.post_content || '').slice(0, 500)}]]></description>
</item>`;
  }).join('\n');

  const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>${siteName}</title>
  <link>${siteUrl}</link>
  <description>${opts.blogdescription || ''}</description>
  <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
  <language>ko</language>
  <atom:link href="${siteUrl}/feed/" rel="self" type="application/rss+xml"/>
  ${items}
</channel>
</rss>`;

  return new Response(rss, {
    headers: { 'Content-Type': 'application/rss+xml; charset=utf-8', 'Cache-Control': `public, max-age=${CACHE_TTL_API}` },
  });
}

async function handleMediaUpload(env, request, siteInfo) {
  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('multipart/form-data')) {
    return new Response(JSON.stringify({ error: 'multipart/form-data ' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const formData = await request.formData();
  const file = formData.get('file') || formData.get('async-upload');
  if (!file || typeof file === 'string') {
    return new Response(JSON.stringify({ error: ' ' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
  }
  const fileName = file.name || 'upload_' + Date.now();
  const mimeType = file.type || 'application/octet-stream';
  const fileSize = file.size || 0;
  const bucket   = siteInfo.storage_bucket || 'media';
  const datePath = new Date().toISOString().slice(0, 7).replace('-', '/');
  const safeName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
  const storagePath = `${siteInfo.site_prefix}/${datePath}/${Date.now()}_${safeName}`;
  const arrayBuffer = await file.arrayBuffer();
  const result = await supabaseUpload(siteInfo, bucket, storagePath, arrayBuffer, mimeType);

  if (!result.ok) {
    if (fileSize < 500 * 1024) {
      const b64 = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
      try {
        await env.DB.prepare(
          `INSERT INTO wp_media (file_name, file_path, mime_type, file_size, upload_date, storage, alt_text) VALUES (?, ?, ?, ?, datetime('now'), 'd1', '')`
        ).bind(safeName, storagePath, mimeType, fileSize).run();
        if (env.CACHE) await env.CACHE.put(`media:${storagePath}`, b64, { metadata: { mimeType, size: fileSize } });
        return new Response(JSON.stringify({ id: Date.now(), url: `/wp-content/uploads/${storagePath}`, title: safeName }), {
          status: 201, headers: { 'Content-Type': 'application/json' },
        });
      } catch {}
    }
    return new Response(JSON.stringify({ error: ' ' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
  try {
    await env.DB.prepare(
      `INSERT INTO wp_media (file_name, file_path, mime_type, file_size, upload_date, storage, alt_text) VALUES (?, ?, ?, ?, datetime('now'), 'supabase', '')`
    ).bind(safeName, result.url, mimeType, fileSize).run();
  } catch {}
  return new Response(JSON.stringify({
    id: Date.now(), url: result.url, title: safeName.replace(/\.[^.]+$/, ''),
    mime_type: mimeType, source_url: result.url, secondary: result.secondary || false,
  }), { status: 201, headers: { 'Content-Type': 'application/json' } });
}

async function revalidatePage(env, siteInfo, url, request) {
  try {
    const { html } = await renderWordPressPage(env, siteInfo, url, request);
    const kvKey = `${siteInfo.site_prefix}:${url.pathname}${url.search}`;
    await kvCachePut(env, kvKey, html, 'text/html; charset=utf-8', 200, CACHE_TTL_HTML);
    const freshResp = new Response(html, {
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`,
        'x-cp-cached': 'edge', 'x-cp-revalidated': '1',
      },
    });
    await edgeCache.put(new Request(url.toString()), freshResp);
  } catch (e) { console.warn('[SWR] revalidation failed:', e.message); }
}

async function handlePurge(env, request, url, siteInfo) {
  const auth = request.headers.get('Authorization') || '';
  const purgeKey = env.PURGE_KEY || '';
  if (purgeKey && auth !== `Bearer ${purgeKey}`) return new Response('Unauthorized', { status: 401 });
  const body = await request.json().catch(() => ({}));
  const paths = body.paths || [url.searchParams.get('path') || '/'];
  let purged = 0;
  for (const p of paths) {
    const kvKey = `${siteInfo.site_prefix}:${p}`;
    try {
      await env.CACHE?.delete(KV_PAGE_PREFIX + kvKey);
      await edgeCache.delete(new Request(`https://${url.hostname}${p}`));
      purged++;
    } catch {}
  }
  return new Response(JSON.stringify({ ok: true, purged, paths }), { headers: { 'Content-Type': 'application/json' } });
}

async function handlePrewarm(env, request, url, siteInfo) {
  const paths = ['/'];
  try {
    const res = await env.DB.prepare(
      `SELECT post_name FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 5`
    ).all();
    for (const r of (res.results || [])) paths.push(`/${r.post_name}/`);
  } catch {}
  const hostname = url.hostname;
  for (const p of paths) {
    const warmUrl = new URL(`https://${hostname}${p}`);
    revalidatePage(env, siteInfo, warmUrl, request).catch(() => {});
  }
  return new Response(JSON.stringify({ ok: true, paths, message: '  ' }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleSitemap(env, siteInfo, url) {
  const siteUrl = `https://${url.hostname}`;
  let posts = [], pages = [];
  try {
    const [pr, pgr] = await Promise.all([
      env.DB.prepare(`SELECT post_name, post_modified FROM wp_posts WHERE post_type='post' AND post_status='publish' ORDER BY post_date DESC LIMIT 1000`).all(),
      env.DB.prepare(`SELECT post_name, post_modified FROM wp_posts WHERE post_type='page' AND post_status='publish' ORDER BY menu_order ASC LIMIT 100`).all(),
    ]);
    posts = pr.results || [];
    pages = pgr.results || [];
  } catch {}
  const urls = [
    `<url><loc>${siteUrl}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>`,
    ...pages.map(p => `<url><loc>${siteUrl}/${p.post_name}/</loc><lastmod>${(p.post_modified||'').slice(0,10)}</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>`),
    ...posts.map(p => `<url><loc>${siteUrl}/${p.post_name}/</loc><lastmod>${(p.post_modified||'').slice(0,10)}</lastmod><changefreq>weekly</changefreq><priority>0.6</priority></url>`),
  ];
  return new Response(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.join('\n')}\n</urlset>`, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': `public, max-age=${CACHE_TTL_API}` },
  });
}

//    
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const hostname = url.hostname.toLowerCase();
  const pathname = url.pathname;
  const method   = request.method;
  const ip       = getClientIP(request);

  // WAF
  const wafResult = wafCheck(request, url);
  if (wafResult.block) {
    if (wafResult.tarpit) await new Promise(r => setTimeout(r, BOT_TARPIT_MS));
    return new Response(
      `<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p> . (${wafResult.reason})</p></body></html>`,
      { status: wafResult.status || 403, headers: { 'Content-Type': 'text/html', 'X-WAF-Block': wafResult.reason } }
    );
  }

  // Rate limit
  const isWrite = !['GET','HEAD','OPTIONS'].includes(method);
  const rlResult = await rateLimitCheck(env, ip, isWrite, pathname);
  if (!rlResult.allowed) {
    if (rlResult.banned) {
      return new Response('IP .', { status: 429, headers: { 'Retry-After': String(DDOS_BAN_TTL) } });
    }
    return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': String(RATE_LIMIT_WIN) } });
  }

  // CloudPress     WordPress  
  // (pass-through  — //   )

  //  
  if (pathname.startsWith('/.well-known/cloudpress-verify/')) {
    const token = pathname.split('/').pop();
    return new Response(`cloudpress-verify=${token}`, { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });
  }

  //  
  const siteInfo = await getSiteInfo(env, hostname);
  if (!siteInfo) {
    return new Response(NOT_FOUND_HTML, { status: 404, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  if (siteInfo.suspended) {
    return new Response(SUSPENDED_HTML, { status: 403, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  // 'pending' 또는 'provisioning' 상태만 준비 중 화면 표시, 나머지는 모두 WP 페이지 렌더링
  if (siteInfo.status === 'pending' || siteInfo.status === 'provisioning') {
    return new Response(PROVISIONING_HTML, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '10' } });
  }

  //   

  // wp-login.php
  if (pathname === '/wp-login.php') {
    return handleWPLogin(env, request, url, siteInfo);
  }

  // wp-admin
  if (pathname.startsWith('/wp-admin')) {
    return handleWPAdmin(env, request, url, siteInfo);
  }

  // REST API
  if (pathname.startsWith('/wp-json/')) {
    return handleWPRestAPI(env, request, url, siteInfo);
  }

  // RSS
  if (pathname === '/feed/' || pathname === '/feed' || url.searchParams.has('feed')) {
    return handleRSSFeed(env, siteInfo, url);
  }

  // Sitemap
  if (pathname === '/wp-sitemap.xml' || pathname === '/sitemap.xml' || pathname === '/sitemap_index.xml') {
    const r = await handleSitemap(env, siteInfo, url);
    ctx.waitUntil(cachePut(ctx, request, r.clone(), CACHE_TTL_API));
    return r;
  }

  //  
  if (pathname === '/wp-admin/async-upload.php' && method === 'POST') {
    return handleMediaUpload(env, request, siteInfo);
  }

  // Purge API
  if (pathname === '/cp-purge' || pathname === '/wp-json/cloudpress/v1/purge') {
    return handlePurge(env, request, url, siteInfo);
  }

  // Prewarm
  if (pathname === '/cp-prewarm') {
    return handlePrewarm(env, request, url, siteInfo);
  }

  // robots.txt
  if (pathname === '/robots.txt') {
    return new Response(
      `User-agent: *\nDisallow: /wp-admin/\nDisallow: /wp-login.php\nDisallow: /wp-json/\nAllow: /wp-admin/admin-ajax.php\nSitemap: https://${hostname}/wp-sitemap.xml\n`,
      { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' } }
    );
  }

  // OPTIONS
  if (method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-WP-Nonce',
      },
    });
  }

  //  
  if (isStaticAsset(pathname)) {
    const cached = await cacheGet(request);
    if (cached && !cached.stale) {
      const r = new Response(cached.response.body, { status: cached.response.status, headers: cached.response.headers });
      r.headers.set('x-cp-hit', 'edge');
      return r;
    }
    if (siteInfo.supabase_url) {
      const mediaPath = pathname.replace('/wp-content/uploads/', '');
      const mediaUrl  = `${siteInfo.supabase_url}/storage/v1/object/public/${siteInfo.storage_bucket || 'media'}/${siteInfo.site_prefix}/${mediaPath}`;
      try {
        const mediaResp = await fetch(mediaUrl, { cf: { cacheTtl: CACHE_TTL_ASSET, cacheEverything: true } });
        if (mediaResp.ok) {
          ctx.waitUntil(cachePut(ctx, request, mediaResp.clone(), CACHE_TTL_ASSET));
          return new Response(mediaResp.body, {
            status: mediaResp.status,
            headers: new Headers({ ...Object.fromEntries(mediaResp.headers), 'Cache-Control': `public, max-age=${CACHE_TTL_ASSET}` }),
          });
        }
      } catch {}
    }
    return new Response('Not Found', { status: 404 });
  }

  //   
  if (!isCacheable(request, url)) {
    const { html, contentData } = await renderWordPressPage(env, siteInfo, url, request);
    return new Response(html, {
      status: contentData.type === '404' ? 404 : 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, private' },
    });
  }

  //   : Edge → KV → SSR 
  const kvKey = `${siteInfo.site_prefix}:${pathname}${url.search}`;

  const edgeHit = await cacheGet(request);
  if (edgeHit) {
    if (!edgeHit.stale) {
      const r = new Response(edgeHit.response.body, { status: edgeHit.response.status, headers: edgeHit.response.headers });
      r.headers.set('x-cp-hit', 'edge');
      return r;
    }
    ctx.waitUntil(revalidatePage(env, siteInfo, url, request));
    const r = new Response(edgeHit.response.body, { status: edgeHit.response.status, headers: edgeHit.response.headers });
    r.headers.set('x-cp-hit', 'edge-stale');
    r.headers.set('x-cp-swr', '1');
    return r;
  }

  const kvHit = await kvCacheGet(env, kvKey);
  if (kvHit) {
    const headers = new Headers({
      'Content-Type': kvHit.contentType || 'text/html; charset=utf-8',
      'Cache-Control': `public, max-age=${CACHE_TTL_HTML}, stale-while-revalidate=${CACHE_TTL_STALE}`,
      'x-cp-hit': 'kv',
    });
    const resp = new Response(kvHit.body, { status: kvHit.status || 200, headers });
    ctx.waitUntil(cachePut(ctx, request, resp.clone(), CACHE_TTL_HTML));
    if (kvHit.stale) {
      ctx.waitUntil(revalidatePage(env, siteInfo, url, request));
      resp.headers.set('x-cp-swr', '1');
    }
    return resp;
  }

  let html, contentData;
  try {
    ({ html, contentData } = await renderWordPressPage(env, siteInfo, url, request));
  } catch (ssrError) {
    console.error('[SSR] render failed:', ssrError?.message);
    return new Response(ERROR_HTML, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '10' } });
  }

  const isNotFound = contentData.type === '404';
  const respStatus = isNotFound ? 404 : 200;
  const ttl        = isNotFound ? 60 : CACHE_TTL_HTML;

  const responseHeaders = new Headers({
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': isNotFound ? 'public, max-age=60' : `public, max-age=${ttl}, stale-while-revalidate=${CACHE_TTL_STALE}`,
    'x-cp-hit': 'miss',
    'x-cp-via': 'cloudpress-ssr',
  });

  if (!isNotFound) {
    ctx.waitUntil(kvCachePut(env, kvKey, html, 'text/html; charset=utf-8', respStatus, ttl));
  }
  const ssrResp = new Response(html, { status: respStatus, headers: responseHeaders });
  if (!isNotFound) ctx.waitUntil(cachePut(ctx, request, ssrResp.clone(), ttl));
  return new Response(html, { status: respStatus, headers: responseHeaders });
}

//  HTML  
const SUSPENDED_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title> </title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{font-size:2rem;margin-bottom:1rem;color:#f55}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box"><h1>  </h1><p>     .</p></div></body></html>`;

const NOT_FOUND_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>   </title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{font-size:2rem;margin-bottom:1rem;color:#fa0}p{color:#aaa;line-height:1.6}a{color:#7af;text-decoration:none}</style>
</head><body><div class="box"><h1>    </h1><p>    .<br><a href="https://cloudpress.site/">CloudPress </a>   .</p></div></body></html>`;

const PROVISIONING_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="10">
<title>  </title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff;text-align:center}.box{padding:2rem;max-width:480px}h1{font-size:1.8rem;margin-bottom:1rem;color:#7af}p{color:#aaa;line-height:1.6}.spin{font-size:2.5rem;display:inline-block;animation:spin 1.2s linear infinite;margin-bottom:1rem}@keyframes spin{to{transform:rotate(360deg)}}</style>
</head><body><div class="box"><div class="spin"></div><h1>  </h1><p>  .</p></div></body></html>`;

const ERROR_HTML = `<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title> </title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;color:#fff}.box{text-align:center;padding:2rem;max-width:480px}h1{color:#f55;margin-bottom:1rem}p{color:#aaa;line-height:1.6}</style>
</head><body><div class="box"><h1>   </h1><p>    .</p></div></body></html>`;

//  Worker  
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      console.error('[worker] Unhandled error:', e?.message || e, e?.stack);
      return new Response(ERROR_HTML, {
        status: 500,
        headers: { 'Content-Type': 'text/html; charset=utf-8' },
      });
    }
  },

  async scheduled(event, env, ctx) {
    try {
      const sites = await env.DB.prepare(
        `SELECT id, site_prefix, primary_domain FROM sites WHERE status='active' AND deleted_at IS NULL LIMIT 100`
      ).all();
      for (const site of (sites.results || [])) {
        if (!site.primary_domain) continue;
        const siteInfo = await getSiteInfo(env, site.primary_domain).catch(() => null);
        if (!siteInfo) continue;
        const homeUrl = new URL(`https://${site.primary_domain}/`);
        ctx.waitUntil(revalidatePage(env, siteInfo, homeUrl, new Request(homeUrl)));
      }
    } catch (e) {
      console.error('[scheduled] ISR error:', e?.message);
    }
  },
};
