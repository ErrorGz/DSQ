'use strict';

/**
 * DSQ 静态网页服务（HTTPS）
 *
 * 零依赖，直接使用 Node 内置模块托管仓库根目录下的静态站点。
 * 默认走 HTTPS，这样页面处于「安全上下文」，navigator.clipboard 等
 * 仅在安全上下文可用的 API 才能正常工作（http 只有 localhost 算安全上下文，
 * 用局域网 IP 访问时不算，所以必须上 https）。
 *
 * 用法：
 *   node server/server.js                          # https://localhost:8443/
 *   HTTPS_PORT=9443 node server/server.js
 *   HTTP_PORT=0 node server/server.js              # 关掉 http->https 跳转
 *   HOST=127.0.0.1 node server/server.js           # 只听本机
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// 站点根目录：server 的上一级（仓库根）
const ROOT = path.resolve(__dirname, '..');
const HOST = process.env.HOST || '0.0.0.0';
const HTTPS_PORT = Number(process.env.HTTPS_PORT) || 8443;
// 设为 0 可关闭 http 跳转服务
const HTTP_PORT = process.env.HTTP_PORT === undefined ? 8080 : Number(process.env.HTTP_PORT);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.eot': 'application/vnd.ms-fontobject',
  '.mp3': 'audio/mpeg',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
};

function contentType(filePath) {
  return MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
}

function sendError(req, res, status, message) {
  const body = `${status} ${message}\n`;
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(req.method === 'HEAD' ? undefined : body);
}

// 将请求路径解析为磁盘路径，并确保不越出 ROOT
function resolvePath(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null; // 非法百分号编码
  }
  if (decoded.includes('\0')) return null;

  const target = path.resolve(ROOT, '.' + path.posix.normalize(decoded));
  if (target !== ROOT && !target.startsWith(ROOT + path.sep)) return null;
  return target;
}

function renderListing(reqUrl, entries) {
  const items = entries
    .map((name) => `<li><a href="${encodeURIComponent(name)}">${name}</a></li>`)
    .join('\n');
  return `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>${reqUrl}</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem}li{line-height:1.8}</style>
</head><body><h1>${reqUrl}</h1><ul>
${items}
</ul></body></html>`;
}

function serveFile(req, res, filePath, stats) {
  const headers = {
    'Content-Type': contentType(filePath),
    // 本地开发：始终拿最新的 html/js/css，避免改完还要强刷
    'Cache-Control': 'no-cache',
    'Last-Modified': stats.mtime.toUTCString(),
    'Accept-Ranges': 'bytes',
  };

  const range = req.headers.range;
  let start = 0;
  let end = stats.size - 1;
  let status = 200;

  if (range) {
    const match = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (match && (match[1] || match[2])) {
      if (match[1]) {
        start = Number(match[1]);
        end = match[2] ? Math.min(Number(match[2]), end) : end;
      } else {
        // bytes=-N 表示最后 N 个字节
        start = Math.max(stats.size - Number(match[2]), 0);
      }
      if (start > end || start >= stats.size) {
        res.writeHead(416, { 'Content-Range': `bytes */${stats.size}` });
        return res.end();
      }
      status = 206;
      headers['Content-Range'] = `bytes ${start}-${end}/${stats.size}`;
    }
  }

  headers['Content-Length'] = end - start + 1;
  res.writeHead(status, headers);
  if (req.method === 'HEAD') return res.end();

  const stream = fs.createReadStream(filePath, { start, end });
  stream.on('error', () => res.destroy());
  stream.pipe(res);
}

function handle(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' });
    return res.end('405 Method Not Allowed\n');
  }

  const pathname = new URL(req.url, 'http://localhost').pathname;
  const filePath = resolvePath(pathname);
  if (!filePath) return sendError(req, res, 400, 'Bad Request');

  fs.stat(filePath, (err, stats) => {
    if (err) return sendError(req, res, 404, 'Not Found');

    // 目录：有 index.html 就返回它，否则列出目录内容
    if (stats.isDirectory()) {
      if (!pathname.endsWith('/')) {
        res.writeHead(301, { Location: encodeURI(pathname) + '/' });
        return res.end();
      }
      const indexPath = path.join(filePath, 'index.html');
      return fs.stat(indexPath, (indexErr, indexStats) => {
        if (!indexErr && indexStats.isFile()) return serveFile(req, res, indexPath, indexStats);
        fs.readdir(filePath, { withFileTypes: true }, (listErr, dirents) => {
          if (listErr) return sendError(req, res, 404, 'Not Found');
          const entries = dirents
            .filter((d) => !d.name.startsWith('.'))
            .map((d) => (d.isDirectory() ? d.name + '/' : d.name))
            .sort((a, b) => a.localeCompare(b));
          const body = Buffer.from(renderListing(pathname, entries), 'utf8');
          res.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Length': body.length,
          });
          res.end(req.method === 'HEAD' ? undefined : body);
        });
      });
    }

    if (!stats.isFile()) return sendError(req, res, 404, 'Not Found');
    serveFile(req, res, filePath, stats);
  });
}

/* ------------------------------------------------------------------ *
 * 证书
 * ------------------------------------------------------------------ */

function loadCredentials() {
  const keyFile = process.env.SSL_KEY || require('./gen-cert').KEY_FILE;
  const certFile = process.env.SSL_CERT || require('./gen-cert').CERT_FILE;

  if (!fs.existsSync(keyFile) || !fs.existsSync(certFile)) {
    if (process.env.SSL_KEY || process.env.SSL_CERT) {
      console.error(`找不到证书文件：\n  key : ${keyFile}\n  cert: ${certFile}`);
      process.exit(1);
    }
    console.log('未找到证书，正在生成自签名证书...');
    require('./gen-cert').generate();
  }

  return { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) };
}

/* ------------------------------------------------------------------ *
 * 启动
 * ------------------------------------------------------------------ */

// http 端口只做一件事：301 跳到 https，保证访问者始终处于安全上下文
function handleHttpRedirect(req, res) {
  const rawHost = req.headers.host || `localhost:${HTTP_PORT}`;
  const hostname = rawHost.replace(/:\d+$/, '');
  // Host 头是客户端可控的，做一次白名单校验避免被拿来构造任意跳转
  const safeHost = /^[A-Za-z0-9.\-]+$/.test(hostname) ? hostname : 'localhost';
  const port = HTTPS_PORT === 443 ? '' : `:${HTTPS_PORT}`;
  res.writeHead(301, { Location: `https://${safeHost}${port}${req.url}` });
  res.end();
}

function listen(server, port, label) {
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`端口 ${port} 已被占用（${label}）。`);
      console.error('换端口重试，例如： HTTPS_PORT=9443 node server/server.js');
      process.exit(1);
    }
    throw err;
  });
  server.listen(port, HOST);
}

const httpsServer = https.createServer(loadCredentials(), handle);
listen(httpsServer, HTTPS_PORT, 'https');

let httpServer = null;
if (HTTP_PORT > 0 && HTTP_PORT !== HTTPS_PORT) {
  httpServer = http.createServer(handleHttpRedirect);
  listen(httpServer, HTTP_PORT, 'http 跳转');
}

httpsServer.on('listening', () => {
  const shown = HOST === '0.0.0.0' ? 'localhost' : HOST;
  console.log(`HTTPS 服务已启动： https://${shown}:${HTTPS_PORT}/`);
  if (httpServer) {
    console.log(`HTTP 跳转已启动：  http://${shown}:${HTTP_PORT}/  ->  https`);
  }
  console.log(`站点根目录： ${ROOT}`);
  console.log('');
  console.log('证书是自签名的，浏览器首次访问会提示「不安全」，点「继续前往」即可；');
  console.log('跳过提示后页面依然是安全上下文，复制到剪贴板可以正常工作。');
  console.log('想彻底去掉警告，可把证书导入「受信任的根证书颁发机构」：');
  console.log('  Import-Certificate -FilePath server\\certs\\cert.pem -CertStoreLocation Cert:\\CurrentUser\\Root');
  console.log('');
  console.log('按 Ctrl+C 停止。');
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    console.log('\n正在关闭服务...');
    let pending = httpServer ? 2 : 1;
    const done = () => {
      if (--pending <= 0) process.exit(0);
    };
    httpsServer.close(done);
    if (httpServer) httpServer.close(done);
  });
}
