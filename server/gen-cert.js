'use strict';

/**
 * 生成自签名证书（零依赖，纯 Node 内置 crypto 手写 DER/X.509）
 *
 * 用途：让本地服务跑在 https 上，从而让页面成为「安全上下文」，
 *       navigator.clipboard 之类的 API 才能正常工作。
 *
 * 用法：
 *   node server/gen-cert.js           # 证书不存在时才生成
 *   node server/gen-cert.js --force   # 强制重新生成（换网络/换 IP 后用这个）
 *
 * 生成的证书会包含 localhost、127.0.0.1、::1 以及本机所有局域网 IPv4 地址，
 * 所以用 http://192.168.x.x 之类的地址访问也不会报证书域名不匹配。
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const CERT_DIR = __dirname + path.sep + 'certs';
const KEY_FILE = path.join(CERT_DIR, 'key.pem');
const CERT_FILE = path.join(CERT_DIR, 'cert.pem');

// 证书有效期（天）
const VALID_DAYS = 3650;

/* ------------------------------------------------------------------ *
 * 极简 DER 编码器
 * ------------------------------------------------------------------ */

function encodeLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n = Math.floor(n / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** tag-length-value */
function tlv(tag, content) {
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

const seq = (...parts) => tlv(0x30, Buffer.concat(parts));
const set = (...parts) => tlv(0x31, Buffer.concat(parts));
const nullValue = () => Buffer.from([0x05, 0x00]);
const utf8String = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const printableString = (s) => tlv(0x13, Buffer.from(s, 'ascii'));

/** 正整数 INTEGER，必要时补前导 0x00 避免被当成负数 */
function integer(buf) {
  let b = buf;
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  b = b.subarray(i);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

function intFromNumber(n) {
  const bytes = [];
  let v = n;
  do {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  } while (v > 0);
  return integer(Buffer.from(bytes));
}

/** 点分十进制 OID 字符串 -> DER */
function oid(str) {
  const parts = str.split('.').map(Number);
  const out = [40 * parts[0] + parts[1]];
  for (const p of parts.slice(2)) {
    const stack = [p & 0x7f];
    let v = Math.floor(p / 128);
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}

/** BIT STRING，unusedBits 为末尾未使用的位数 */
function bitString(bytes, unusedBits = 0) {
  return tlv(0x03, Buffer.concat([Buffer.from([unusedBits]), bytes]));
}

/** [n] 上下文标签，constructed=false 时用于隐式原始类型（如 SAN 里的 dNSName） */
function ctx(n, content, constructed = true) {
  return tlv((constructed ? 0xa0 : 0x80) | n, content);
}

/** UTCTime: YYMMDDHHMMSSZ */
function utcTime(date) {
  const p = (n) => String(n).padStart(2, '0');
  const s =
    p(date.getUTCFullYear() % 100) +
    p(date.getUTCMonth() + 1) +
    p(date.getUTCDate()) +
    p(date.getUTCHours()) +
    p(date.getUTCMinutes()) +
    p(date.getUTCSeconds()) +
    'Z';
  return tlv(0x17, Buffer.from(s, 'ascii'));
}

function pem(label, der) {
  const lines = der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}

/* ------------------------------------------------------------------ *
 * 证书内容
 * ------------------------------------------------------------------ */

/** 收集需要写进证书的地址：localhost + 回环 + 所有局域网 IPv4 */
function collectHosts() {
  const dnsNames = new Set(['localhost']);
  const ipAddresses = new Set(['127.0.0.1', '::1']);

  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const info of ifaces[name] || []) {
      if (info.internal) continue;
      // 只收 IPv4，IPv6 链路本地地址写进证书没意义
      if (info.family === 'IPv4') ipAddresses.add(info.address);
    }
  }
  // hostname 也带上，方便用机器名访问
  if (os.hostname()) dnsNames.add(os.hostname());

  return { dnsNames: [...dnsNames], ipAddresses: [...ipAddresses] };
}

function ipToBytes(ip) {
  if (ip.includes(':')) {
    // IPv6 -> 16 字节
    const buf = Buffer.alloc(16);
    const [head, tail] = ip.split('::');
    const headParts = head ? head.split(':').filter(Boolean) : [];
    const tailParts = tail !== undefined && tail ? tail.split(':').filter(Boolean) : [];
    headParts.forEach((h, i) => buf.writeUInt16BE(parseInt(h, 16), i * 2));
    tailParts.forEach((t, i) => buf.writeUInt16BE(parseInt(t, 16), 16 - (tailParts.length - i) * 2));
    return buf;
  }
  return Buffer.from(ip.split('.').map(Number));
}

function buildCertificate(privateKey, publicKeyDer, hosts) {
  const sha256WithRsa = seq(oid('1.2.840.113549.1.1.11'), nullValue());

  const subject = seq(
    set(seq(oid('2.5.4.6'), printableString('CN'))), // C  = CN
    set(seq(oid('2.5.4.10'), utf8String('DSQ Local Dev'))), // O  = 组织
    set(seq(oid('2.5.4.3'), utf8String('localhost'))) // CN = localhost
  );

  const serial = integer(crypto.randomBytes(16).fill(0, 0, 1).subarray(0));

  const now = new Date();
  const notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 回拨一天，容忍时钟偏差
  const notAfter = new Date(now.getTime() + VALID_DAYS * 24 * 60 * 60 * 1000);

  // SubjectAltName：现代浏览器只看这里，不看 CN
  const sanEntries = [
    ...hosts.dnsNames.map((d) => tlv(0x82, Buffer.from(d, 'ascii'))),
    ...hosts.ipAddresses.map((ip) => tlv(0x87, ipToBytes(ip))),
  ];
  const subjectAltName = seq(oid('2.5.29.17'), tlv(0x04, seq(...sanEntries)));

  // basicConstraints: CA:FALSE（叶子证书），critical
  const basicConstraints = seq(oid('2.5.29.19'), Buffer.from([0x01, 0x01, 0xff]), tlv(0x04, seq()));

  // keyUsage: digitalSignature + keyEncipherment，critical
  // 注意 extnValue 一律是包住真实值的 OCTET STRING（0xa0 = 101，即 bit0 与 bit2 置位）
  const keyUsage = seq(
    oid('2.5.29.15'),
    Buffer.from([0x01, 0x01, 0xff]),
    tlv(0x04, bitString(Buffer.from([0xa0]), 5))
  );

  // extendedKeyUsage: serverAuth + clientAuth
  const extKeyUsage = seq(
    oid('2.5.29.37'),
    tlv(0x04, seq(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2')))
  );

  const tbs = seq(
    ctx(0, intFromNumber(2)), // version v3
    serial,
    sha256WithRsa,
    subject, // issuer == subject（自签名）
    seq(utcTime(notBefore), utcTime(notAfter)),
    subject,
    publicKeyDer, // SubjectPublicKeyInfo，直接由 crypto 导出
    ctx(3, seq(basicConstraints, keyUsage, extKeyUsage, subjectAltName))
  );

  const signature = crypto.createSign('sha256').update(tbs).sign(privateKey);
  return seq(tbs, sha256WithRsa, bitString(signature));
}

/**
 * 生成证书文件。已存在且未指定 force 时直接跳过。
 * @returns {{keyFile: string, certFile: string, hosts: object}}
 */
function generate({ force = false } = {}) {
  if (!force && fs.existsSync(KEY_FILE) && fs.existsSync(CERT_FILE)) {
    return { keyFile: KEY_FILE, certFile: CERT_FILE, hosts: null, skipped: true };
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const hosts = collectHosts();
  const certDer = buildCertificate(privateKey, spkiDer, hosts);

  fs.mkdirSync(CERT_DIR, { recursive: true });
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(CERT_FILE, pem('CERTIFICATE', certDer));

  return { keyFile: KEY_FILE, certFile: CERT_FILE, hosts };
}

module.exports = { generate, KEY_FILE, CERT_FILE, CERT_DIR };

if (require.main === module) {
  const force = process.argv.includes('--force');
  const res = generate({ force });
  if (res.skipped) {
    console.log('证书已存在，跳过生成。要重新生成请加 --force');
    console.log('  证书： ' + res.certFile);
    console.log('  私钥： ' + res.keyFile);
  } else {
    console.log('自签名证书已生成：');
    console.log('  证书： ' + res.certFile);
    console.log('  私钥： ' + res.keyFile);
    console.log('  域名： ' + res.hosts.dnsNames.join(', '));
    console.log('  地址： ' + res.hosts.ipAddresses.join(', '));
  }
}
