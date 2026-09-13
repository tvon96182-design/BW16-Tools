#ifndef WEB_ADMIN_H
#define WEB_ADMIN_H

// Tabbed Web UI: Home + Custom SSID Beacon + Handshake Capture
const char WEB_ADMIN_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BW16 Tools · Giao diện quản trị</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:Arial,Helvetica,sans-serif;background:#f5f6f8;color:#222;padding:16px}
    .shell{max-width:800px;margin:0 auto;background:#fff;border:1px solid #e8e8e8;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.06);overflow:hidden}
    .brand{padding:16px 18px;border-bottom:1px solid #eee;background:linear-gradient(180deg,#4caf50,#45a049);color:#fff}
    .brand h1{font-size:18px;margin:0}
    .tabs{display:flex;gap:0;border-bottom:1px solid #eee;background:#fafafa}
    .tab{flex:1;text-align:center;padding:12px 10px;cursor:pointer;font-weight:600;color:#555}
    .tab.active{background:#fff;border-bottom:2px solid #4caf50;color:#2e7d32}
    .page{display:none;padding:16px}
    .page.active{display:block}
    h2{font-size:16px;margin-bottom:8px;color:#333;display:flex;flex-wrap:nowrap;justify-content:center}
    p{margin:8px 0;color:#555;line-height:1.5}
    .card{border:1px solid #eee;border-radius:8px;padding:12px;background:#fafafa}
    #HomeCard{display:flex;justify-content:center;flex-wrap:wrap}
    label{display:block;color:#000;font-size:14px;margin-top:6px}
    input[type=text]{width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:6px}
    .row{margin-top:8px;text-align:center}
    .btn{padding:10px 14px;border:0;border-radius:6px;color:#fff;cursor:pointer;margin-right:8px;display:inline-block}
    .btn-danger{background:#f44336}
    .btn-warning{background:#ff9800}
    .status{margin-top:10px;padding:10px;border-radius:6px;background:#e8f5e9;border:1px solid #4caf50;color:#2e7d32;text-align:center}
    .muted{color:#777;font-size:12px;margin-top:8px}
    .radio-row{text-align:center;margin: 20px;}
    .radio-row>label{display:inline-block;margin-right:12px}
    .muted{text-align:center}
    #mode-help,#mode-help:visited{color:orange}
    footer{padding:12px;text-align:center;color:#999;border-top:1px solid #eee;font-size:12px}
    @media screen and (max-width: 800px) {#ap-select{max-width: 300px;}}
    /* Start-capture loading spinner */
    .spinner{display:none;width:16px;height:16px;border:2px solid #ccc;border-top-color:#4caf50;border-radius:50%;animation:spin 0.8s linear infinite;margin-left:8px;vertical-align:middle}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
  <script>
    function $(id){return document.getElementById(id)}
    function setActive(idx){
      const tabs=document.querySelectorAll('.tab');
      const pages=document.querySelectorAll('.page');
      tabs.forEach((t,i)=>t.classList.toggle('active', i===idx));
      pages.forEach((p,i)=>p.classList.toggle('active', i===idx));
    }
    function show(msg,type){
      const d=document.createElement('div');
      d.textContent=msg; d.className='toast';
      d.style.cssText='position:fixed;left:50%;top:16px;transform:translateX(-50%);background:'+(type==='success'?'#4caf50':'#f44336')+';color:#fff;padding:8px 12px;border-radius:6px;box-shadow:0 4px 10px rgba(0,0,0,.2);z-index:9999;';
      document.body.appendChild(d); setTimeout(()=>d.remove(),2000);
    }
    function refresh(){
      try{ fetch('/status').then(()=>{}).catch(()=>{});}catch(e){}
    }
    function startCustom(){
      const ssid=$('ssid').value.trim(); if(!ssid){show('Vui lòng nhập SSID');return}
      if(!confirm('Xác nhận sẽ gửi yêu cầu tấn công và đóng AP hiện tại. Dừng Web UI để kết thúc')) return;
      const band=document.querySelector('input[name="band"]:checked').value;
      const body='ssid='+encodeURIComponent(ssid)+'&band='+encodeURIComponent(band);
      try { fetch('/custom-beacon',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}); } catch(e) {}
      show('Đã bắt đầu, sẽ ngắt kết nối AP này!');
    }
    function stopAll(){
      fetch('/stop',{method:'POST'}).then(r=>r.json()).then(()=>{ show('Đã dừng','success'); })
        .catch(()=>show('Yêu cầu thất bại'))
    }
    function startScan(){
      if(!confirm('Sẽ tạm tắt AP để quét, kết nối bị ngắt rồi tự khôi phục. Tiếp tục?')) return;
      $('scan-status').textContent = 'Đang quét...';
      fetch('/handshake/scan',{method:'POST'})
        .then(()=>{ pollScanStatus(); })
        .catch(()=>show('Khởi động quét thất bại'))
    }
    function pollScanStatus(){
      fetch('/handshake/scan-status').then(r=>r.json()).then(st=>{
        if(st.done){ loadOptions(); $('scan-status').textContent = 'Đã hoàn thành'; }
        else setTimeout(pollScanStatus, 1500);
      }).catch(()=>setTimeout(pollScanStatus, 2000));
    }
    function loadOptions(){
      fetch('/handshake/options').then(r=>r.text()).then(html=>{
        const sel=$('ap-select');
        sel.innerHTML = html;
        if(sel.options && sel.options.length>0){ sel.selectedIndex = 0; }
      });
    }
    function selectNetwork(bssid){
      fetch('/handshake/select?bssid='+encodeURIComponent(bssid),{method:'POST'}).then(()=>{
        show('Đã chọn mạng','success');
        document.getElementById('selected-network').style.display = 'block';
      }).catch(()=>show('Chọn thất bại'))
    }
    function startHandshake(){
      const sel=$('ap-select');
      const bssid = sel && sel.value ? sel.value.trim() : '';
      if(!bssid){ show('Hãy chọn một AP mục tiêu trước'); return; }
      const modeEl = document.querySelector('input[name="capmode"]:checked');
      const mode = modeEl ? modeEl.value : 'active';
      
      // show usage confirm dialog
      const confirmMsg = '⬇ Hướng dẫn ⬇\n\n' +
        'Sau khi bắt đầu, Web UI có thể bị ngắt. LED tắt khi đang bắt gói, LED xanh sáng lại khi xong. Kết nối lại Web UI để tải handshake.\n\n' +
        '⚠ Lưu ý: Khởi động lại thiết bị hoặc Web UI sẽ mất handshake đã bắt, hãy lưu kịp thời!\n\nKhông thể dừng giữa chừng, muốn dừng hãy nhấn RST' +
        'Xác nhận bắt đầu bắt gói?';
      
      if(!confirm(confirmMsg)) return;
      
      const body = 'bssid='+encodeURIComponent(bssid);
      // show spinner, disable btn until capture starts
      const spinner = $('start-loading');
      const startBtn = event && event.target && event.target.closest('button') ? event.target.closest('button') : null;
      if (spinner) spinner.style.display = 'inline-block';
      if (startBtn) startBtn.disabled = true;
      fetch('/handshake/select',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body})
        .then(()=>{
          const body2 = 'mode='+encodeURIComponent(mode);
          return fetch('/handshake/capture',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body: body2});
        })
        .then(()=>{
          show('Bắt đầu bắt gói','success');
          document.getElementById('handshake-status').style.display = 'block';
          if (spinner) spinner.style.display = 'none';
          if (startBtn) startBtn.disabled = false;
          setTimeout(checkHandshakeStatus, 1500);
        })
        .catch(()=>{ if (spinner) spinner.style.display = 'none'; if (startBtn) startBtn.disabled = false; show('Khởi động thất bại'); })
    }
    function stopHandshake(){
      fetch('/handshake/stop',{method:'POST'}).then(()=>{
        show('Đã dừng bắt gói','success');
        document.getElementById('handshake-status').style.display = 'none';
      }).catch(()=>show('Dừng thất bại'))
    }
    function checkHandshakeStatus(){
      fetch('/handshake/status').then(r=>r.json()).then(data=>{
        const hs = $('handshake-status');
        const dl = $('pcap-download');
        const saved = $('saved-section');
        const savedInfo = $('saved-info');
        const savedEmpty = $('saved-empty');
        const savedCounts = $('saved-counts');
        const savedTime = $('saved-time');
        if(data.justCaptured){
          alert('Đã bắt được handshake!');
          // justCaptured cleared by backend on next status or delete
          location.reload();
          return;
        }
        if(data.captured){ hs.style.display='none'; dl.style.display='block'; }
        else if(data.running){ hs.style.display='block'; dl.style.display='none'; setTimeout(checkHandshakeStatus, 2000); }
        else { hs.style.display='none'; dl.style.display='none'; }
        // update saved section
        if(data.pcapSize && data.pcapSize>0){
          saved.style.display='block'; savedEmpty.style.display='none'; savedInfo.style.display='block';
          savedCounts.textContent = 'Handshake Count: '+data.hsCount+'/4, Management Frames: '+data.mgmtCount+'/10';
          savedTime.textContent = 'Thời gian (ms): '+data.ts;
        } else {
          saved.style.display='block'; savedInfo.style.display='none'; savedEmpty.style.display='block';
        }
      }).catch(()=>{})
    }
    function deleteSaved(){
      if(!confirm('Xóa handshake và dữ liệu thống kê đã lưu?')) return;
      fetch('/handshake/delete',{method:'POST'}).then(()=>{ show('Đã xóa','success'); location.reload(); })
        .catch(()=>show('Xóa thất bại'))
    }
    function downloadPcap(){
      const a=document.createElement('a');
      a.href='/handshake/download';
      a.download='capture.pcap';
      document.body.appendChild(a);
      a.click();
      a.remove();
    }
    function showModeHelp(){
      alert('Chế độ thụ động: chỉ bắt gói, không gây nhiễu, chậm hơn nhưng tỷ lệ hợp lệ ~99%.

Chế độ chủ động: vừa bắt vừa gửi deauth, nhanh hơn nhưng có thể bắt nhầm frame.

Chế độ hiệu quả: định kỳ tạm dừng bắt để gửi deauth, tỷ lệ hợp lệ >90%, ít gói lỗi.

Gợi ý: ưu tiên chế độ chủ động; nếu bắt quá nhanh (khoảng 1s) hãy thử hiệu quả hoặc thụ động.

Lưu ý: Handshake Count nên là 4/4. Nếu 0/4 hoặc 2/4 thường là gói không đầy đủ.');
    }
    document.addEventListener('DOMContentLoaded', ()=>{
      setActive(0);
      refresh(); setInterval(refresh,2000);
      // load list only, no auto scan
      loadOptions();
      // init saved section + status poll
      checkHandshakeStatus();
    });
  </script>
</head>
<body>
  <div class="shell">
    <div class="brand"><h1>😽 BW16 Tools · Web UI</h1></div>
    <div class="tabs">
      <div class="tab active" onclick="setActive(0)">Trang chủ / HD</div>
      <div class="tab" onclick="setActive(1)">Beacon</div>
      <div class="tab" onclick="setActive(2)">Bắt Handshake</div>
    </div>
    <div class="page active" id="page-home">
      <h2>📌 Về dự án</h2>
      <div class="card" id="HomeCard">
        <p>github.com/FlyingIceyyds/Bw16-Tools</p>
        <p>Mã nguồn mở GPL-3.0, không được bán lại hoặc đóng nguồn</p>
      </div>
      <h2 style="margin-top:14px;">📑 Hướng dẫn Web UI</h2>
      <div class="status">Web UI chỉ bổ sung các chức năng OLED chưa có, không trùng lặp</div>
    </div>
    <div class="page" id="page-beacon">
      <h2>📡 Beacon SSID tùy chỉnh</h2>
      <div class="card">
        <label style="text-align:center;">🖋️ Tên SSID</label>
        <input id="ssid" type="text" placeholder="Nhập SSID cần phát">
        <label style="margin-top:8px;text-align:center;">🌐 Băng tần phát</label>
        <div class="radio-row">
          <label><input type="radio" name="band" value="mixed" checked> Hỗn hợp (2.4G+5G)</label>
          <label><input type="radio" name="band" value="2g"> 2.4G</label>
          <label><input type="radio" name="band" value="5g"> 5G</label>
        </div>
        <div class="row">
          <button class="btn btn-danger" onclick="startCustom()">Bắt đầu</button>
          <button class="btn btn-warning" onclick="stopAll()">Dừng</button>
        </div>
        <div class="muted">Web UI tốn tài nguyên, có thể ảnh hưởng hiệu suất. Nên dùng menu OLED nếu không cần thiết</div>
      </div>
    </div>
    <div class="page" id="page-handshake">
      <h2>🔐 Bắt Handshake WPA/WPA2</h2>
      <div class="card">
        <p style="text-align:center;">Chức năng này bắt gói handshake 4-way WPA/WPA2</p>
        <p style="color:red;text-align:center;">Từ v2.2 nên dùng chức năng Quick Capture trên OLED!</p>
        <div class="row" style="gap:8px; align-items:center; justify-content:center; margin-top:8px;">
          <select id="ap-select" style="min-width:80%; padding:8px;">
            <option value="">Đang tải danh sách...</option>
          </select><br />
          <span id="scan-status" class="muted">Đang tải</span>
        </div>
        <div class="row" style="margin-top: 12px;">
          <div class="radio-row" style="margin-bottom:10px;">
            <label><input type="radio" name="capmode" value="active" checked> Chế độ chủ động</label>
            <label><input type="radio" name="capmode" value="passive"> Chế độ thụ động</label>
            <label><input type="radio" name="capmode" value="efficient"> Chế độ hiệu quả</label><br />
            <a id="mode-help" href="javascript:void(0)" onclick="showModeHelp()" style="margin-left:8px;line-height:50px;">Xem hướng dẫn chế độ</a>
          </div>
          <button class="btn btn-danger" onclick="startHandshake(event)">Bắt đầu</button><span id="start-loading" class="spinner"></span>
          <button class="btn btn-warning" onclick="stopHandshake()">Dừng</button>
          <button class="btn" style="background:#607d8b" onclick="startScan()">Quét lại</button>
        </div>
        <div id="handshake-status" style="margin-top: 16px; display: none;">
          <div class="status">Đang bắt gói, vui lòng chờ...</div>
        </div>
        <div id="pcap-download" style="margin-top: 16px; display: none;">
          <div class="status">Đã bắt được handshake!</div>
        </div>
        <div id="saved-section" class="card" style="margin-top:12px; display:none;">
          <div id="saved-empty" class="muted" style="display:none;color:#f44336;">Chưa có handshake, hãy bắt đầu bắt gói</div>
          <div id="saved-info" style="display:none;">
            <div id="saved-counts" class="status" style="margin-bottom:8px;"></div>
            <div id="saved-time" class="muted" style="margin-bottom:8px;"></div>
            <div class="row">
              <button class="btn btn-danger" onclick="downloadPcap()">Tải file PCAP</button>
              <button class="btn btn-warning" onclick="deleteSaved()">Xóa</button>
            </div>
          </div>
        </div>
        <div class="muted">Cảnh báo: Chỉ dùng cho mục đích nghiên cứu và giáo dục an ninh</div>
      </div>
    </div>
    <footer>© 2025 Bw16-Tools</footer>
  </div>
</body>
</html>
)rawliteral";

#endif



