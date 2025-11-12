// netlify/edge-functions/gate-questionnaire.js
// Exige un token HMAC (via ?t=... ou x-fc-token). Sinon → page blanche "Site privé".

const textEncoder = new TextEncoder();

function b64urlEncode(bytes) {
  let bin = '';
  bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
}
function b64urlDecode(str) {
  const pad = s => s + '==='.slice((s.length + 3) % 4);
  const b64 = pad(str).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
async function hmacSHA256(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(data));
  return new Uint8Array(sig);
}

function privatePage() {
  const html = `<!doctype html><meta charset="utf-8">
<title>Site privé</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<style>
  :root{color-scheme:light;}
  html,body{height:100%;margin:0;background:#fff;}
  .wrap{min-height:100%;display:grid;place-items:center;}
  .txt{font-family:system-ui,-apple-system,Segoe UI,Inter,Roboto,Arial,sans-serif;
       color:#111;font-size:16px;font-weight:600;}
</style>
<div class="wrap"><div class="txt">Site privé</div></div>`;
  return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

export default async (request, context) => {
  const secret = Deno.env.get('FC_SHARED_SECRET') || '';
  if (!secret) {
    // Même en cas de mauvaise conf, on n’expose rien : page privée
    return privatePage();
  }

  const REQUIRED_SRC_PREFIX = 'https://appli.files-coaching.com/dashboard/profile';

  const url = new URL(request.url);
  const token = url.searchParams.get('t') || request.headers.get('x-fc-token') || '';

  let ok = false;
  try {
    // Token = base64url(payload).base64url(signature)
    const [payloadB64, sigB64] = token.split('.');
    if (payloadB64 && sigB64) {
      const expectedSigB64 = b64urlEncode(await hmacSHA256(secret, payloadB64));
      if (expectedSigB64 === sigB64) {
        const payloadJson = new TextDecoder().decode(b64urlDecode(payloadB64));
        const payload = JSON.parse(payloadJson);
        const now = Date.now();

        const expOk = typeof payload.exp === 'number' && now <= payload.exp;
        const audOk = !payload.aud || payload.aud === 'questionnaire';
        const srcOk = typeof payload.src === 'string' && payload.src.startsWith(REQUIRED_SRC_PREFIX);

        ok = expOk && audOk && srcOk;
      }
    }
  } catch {
    ok = false;
  }

  if (!ok) {
    // Accès direct / token invalide → page blanche "Site privé"
    return privatePage();
  }

  // Token valide → on laisse passer vers la page
  return context.next();
};
