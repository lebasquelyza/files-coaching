const textEncoder = new TextEncoder();

function b64urlEncode(bytes) {
  let bin = ''; bytes.forEach(b => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function b64urlDecode(str) {
  const pad = s => s + '==='.slice((s.length + 3) % 4);
  const b64 = pad(str).replace(/-/g,'+').replace(/_/g,'/');
  const bin = atob(b64);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
async function hmacSHA256(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', textEncoder.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(data));
  return new Uint8Array(sig);
}

export default async (request, context) => {
  const secret = Deno.env.get('FC_SHARED_SECRET') || '';
  if (!secret) return new Response('Misconfiguration: FC_SHARED_SECRET missing', { status: 500 });

  const REQUIRED_SRC = 'https://appli.files-coaching.com/dashboard/profile';

  const url = new URL(request.url);
  const token = url.searchParams.get('t') || request.headers.get('x-fc-token') || '';

  let ok = false;
  try {
    const [payloadB64, sigB64] = token.split('.');
    if (payloadB64 && sigB64) {
      const expectedSigB64 = b64urlEncode(await hmacSHA256(secret, payloadB64));
      if (expectedSigB64 === sigB64) {
        const payloadJson = new TextDecoder().decode(b64urlDecode(payloadB64));
        const payload = JSON.parse(payloadJson);
        const now = Date.now();

        // Checks: expiration + audience + source (chemin exact)
        const audOk = !payload.aud || payload.aud === 'questionnaire';
        const srcOk = payload.src === REQUIRED_SRC;
        const expOk = typeof payload.exp === 'number' && now <= payload.exp;

        // (Optionnel mais conseillé) Referer côté client pour plus de stricte — non déterminant
        const referer = request.headers.get('referer') || '';
        const refererOk = !referer || referer.startsWith(REQUIRED_SRC);

        ok = expOk && audOk && srcOk && refererOk;
      }
    }
  } catch { ok = false; }

  if (!ok) {
    const html = `<!doctype html><meta charset="utf-8">
<title>Accès refusé</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:system-ui,-apple-system,Segoe UI,Inter,Roboto;padding:24px;color:#111}
.card{max-width:640px;margin:10vh auto;border:1px solid #e5e7eb;border-radius:14px;padding:24px}
a{color:#16a34a;text-decoration:none;font-weight:600}</style>
<div class="card">
  <h1>Accès refusé</h1>
  <p>Ce questionnaire n’est accessible que depuis l’application Files Coaching (profil).</p>
  <p><a href="https://appli.files-coaching.com/dashboard/profile">Aller à mon profil</a></p>
</div>`;
    return new Response(html, { status: 403, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  return context.next();
};
