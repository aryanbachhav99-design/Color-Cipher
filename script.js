// COLOR BLEND CIPHER — upgraded visual lab

const $ = id => document.getElementById(id);
let secretKey = null;
let keyLayers = [];
let lastCipherPackage = null;
let lastCiphertext = [];
let showRGB = false;

function toast(msg){const t=$("toast");t.textContent=msg;t.classList.add("show");setTimeout(()=>t.classList.remove("show"),2200)}

function randomByte(){return Math.floor(Math.random()*256)}
function rgbToHex(r,g,b){return "#"+[r,g,b].map(v=>Math.max(0,Math.min(255,Math.round(v))).toString(16).padStart(2,"0")).join("").toUpperCase()}
function hexToRgb(hex){hex=hex.replace("#","");return{r:parseInt(hex.slice(0,2),16),g:parseInt(hex.slice(2,4),16),b:parseInt(hex.slice(4,6),16)}}
function hashString(str){let h=2166136261;for(let i=0;i<str.length;i++){h^=str.charCodeAt(i);h=Math.imul(h,16777619)}return h>>>0}
function bytesToKey(bytes){return{r:bytes[0],g:bytes[1],b:bytes[2]}}
function keyCodeFromKey(k){return "CBC-"+[k.r,k.g,k.b].map(v=>v.toString(16).padStart(2,"0")).join("").toUpperCase()}
function keyFromCode(code){if(!/^CBC-[0-9A-Fa-f]{6}$/.test(code.trim()))return null;return hexToRgb("#"+code.trim().slice(4))}
function deriveLayers(k){return[
 {r:k.r,g:k.g,b:k.b},
 {r:(k.g+83)%256,g:(k.b+47)%256,b:(k.r+131)%256},
 {r:(k.b+197)%256,g:(k.r+29)%256,b:(k.g+71)%256}
]}
function generateSecretKey(){
 secretKey={r:randomByte(),g:randomByte(),b:randomByte()};
 keyLayers=deriveLayers(secretKey);
 updateKeyUI(); renderLayers(); toast("New secret key generated");
}
function setSecretKey(k){
 secretKey={r:k.r,g:k.g,b:k.b};keyLayers=deriveLayers(secretKey);updateKeyUI();renderLayers()
}
function updateKeyUI(){
 const hex=rgbToHex(secretKey.r,secretKey.g,secretKey.b), code=keyCodeFromKey(secretKey);
 $("keyPreview").style.background=hex;$("keyCode").textContent=code;$("decryptKey").value=code;
}
function renderLayers(){
 $("layerList").innerHTML=keyLayers.map((k,i)=>`<div class="layer"><span class="layer-dot" style="background:${rgbToHex(k.r,k.g,k.b)}"></span>Layer ${i+1} ${rgbToHex(k.r,k.g,k.b)}</div>`).join("")
}
function charToColor(ch){const x=ch.charCodeAt(0);return{r:x,g:(x*2)%256,b:(x*3)%256}}
function blend(a,k){return{r:(a.r+k.r)/2,g:(a.g+k.g)/2,b:(a.b+k.b)/2}}
function unblend(c,k){return{r:2*c.r-k.r,g:2*c.g-k.g,b:2*c.b-k.b}}
function rotatedKey(base,index){return{r:(base.r+index*37)%256,g:(base.g+index*73)%256,b:(base.b+index*109)%256}}

function encryptText(){
 const text=$("plaintext").value;if(!text){toast("Enter plaintext first");return}
 const rotate=$("perCharKey").checked;lastCiphertext=[];const steps=[];
 for(let i=0;i<text.length;i++){
   let c=charToColor(text[i]);const before={...c};const layers=rotate?keyLayers.map(k=>rotatedKey(k,i)):keyLayers;
   layers.forEach(k=>c=blend(c,k));
   lastCiphertext.push(c);
   if(i<8)steps.push({char:text[i],ascii:text.charCodeAt(i),before,after:c,layers})
 }
 lastCipherPackage={type:"COLOR_BLEND_CIPHER",version:3,algorithm:"RGB-BLEND-MULTI-LAYER",keyRequired:true,keyLayers:keyLayers.length,rotation:rotate,data:lastCiphertext};
 $("ciphertext").value=JSON.stringify(lastCipherPackage);
 renderCipherColors();renderSteps(steps);toast("Text encrypted")
}
function renderCipherColors(){
 const box=$("cipherColors");box.innerHTML="";
 if(!lastCiphertext.length){box.innerHTML='<p class="empty">Encrypt text to see the color ciphertext.</p>';return}
 lastCiphertext.forEach((c,i)=>{
   const d=document.createElement("div");d.className="cipher-color";d.style.background=rgbToHex(c.r,c.g,c.b);d.title=`RGB ${c.r.toFixed(4)}, ${c.g.toFixed(4)}, ${c.b.toFixed(4)}`;
   d.innerHTML=`<span class="cipher-index">${i+1}</span>`;
   if(showRGB)d.innerHTML+=`<span class="rgb-label">${c.r.toFixed(0)},${c.g.toFixed(0)},${c.b.toFixed(0)}</span>`;
   box.appendChild(d)
 })
}
function renderSteps(steps){
 if(!steps.length){$("stepViewer").innerHTML='<p class="empty">Encrypt a message to inspect the transformation.</p>';return}
 $("stepViewer").innerHTML=steps.map(s=>`<div class="step"><div class="step-color" style="background:${rgbToHex(s.after.r,s.after.g,s.after.b)}"></div><div><strong>${escapeHtml(s.char)}</strong> → ASCII ${s.ascii} → Base RGB (${s.before.r}, ${s.before.g}, ${s.before.b}) → ${s.layers.length} color layer(s) → Cipher RGB (${s.after.r.toFixed(2)}, ${s.after.g.toFixed(2)}, ${s.after.b.toFixed(2)})</div></div>`).join("")
}
function escapeHtml(s){return s.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}

function decryptText(){
 const raw=$("ciphertext").value.trim();if(!raw){toast("Paste ciphertext first");return}
 const code=$("decryptKey").value.trim();const k=keyFromCode(code);if(!k){toast("Enter a valid CBC-XXXXXX key");return}
 let pkg;try{pkg=JSON.parse(raw)}catch(e){toast("Invalid .cbc data");return}
 if(pkg.type!=="COLOR_BLEND_CIPHER"||!Array.isArray(pkg.data)){toast("Invalid Color Blend Cipher data");return}
 const layers=deriveLayers(k),rotate=!!pkg.rotation;let out="";
 for(let i=0;i<pkg.data.length;i++){
   let c={...pkg.data[i]};const use=rotate?layers.map(x=>rotatedKey(x,i)):layers;
   for(let j=use.length-1;j>=0;j--)c=unblend(c,use[j]);
   const ascii=Math.round(c.r);if(ascii<0||ascii>65535){toast("Wrong key or corrupted data");return}out+=String.fromCharCode(ascii)
 }
 $("decryptOutput").value=out;setSecretKey(k);toast("Decryption successful")
}

function toggleRgb(){showRGB=!showRGB;$("toggleRgbBtn").textContent=showRGB?"Hide RGB":"Show RGB";renderCipherColors()}
function copyText(value){navigator.clipboard.writeText(value).then(()=>toast("Copied")).catch(()=>{const a=document.createElement("textarea");a.value=value;document.body.appendChild(a);a.select();document.execCommand("copy");a.remove();toast("Copied")})}
function copyCipher(){if(!lastCipherPackage){toast("Encrypt something first");return}copyText(JSON.stringify(lastCipherPackage))}
function downloadBlob(blob,name){const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
function downloadCbc(){if(!lastCipherPackage){toast("Encrypt something first");return}downloadBlob(new Blob([JSON.stringify(lastCipherPackage,null,2)],{type:"application/json"}),"message.cbc")}

function rotateLayers(){if(!secretKey){generateSecretKey();return}keyLayers=deriveLayers({r:randomByte(),g:randomByte(),b:randomByte()});renderLayers();toast("Color layers rotated")}
function passwordKey(){
 const p=$("passwordInput").value;if(!p){toast("Enter a password");return}
 let h=hashString(p),bytes=[];for(let i=0;i<3;i++){h=Math.imul(h^ (h>>>13),1274126177)>>>0;bytes.push(h&255)}
 setSecretKey(bytesToKey(bytes));toast("Password-derived key generated")
}

document.addEventListener("DOMContentLoaded",()=>{
 generateSecretKey();
 document.querySelectorAll(".tab").forEach(t=>t.addEventListener("click",()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));document.querySelectorAll(".tab-panel").forEach(x=>x.classList.remove("active"));t.classList.add("active");$(t.dataset.tab).classList.add("active")}));
 $("newKeyBtn").onclick=generateSecretKey;$("copyKeyBtn").onclick=()=>copyText($("keyCode").textContent);$("useCurrentKeyBtn").onclick=()=>{$("decryptKey").value=$("keyCode").textContent};$("rotateBtn").onclick=rotateLayers;$("encryptBtn").onclick=encryptText;$("decryptBtn").onclick=decryptText;$("toggleRgbBtn").onclick=toggleRgb;$("copyCipherBtn").onclick=copyCipher;$("downloadCbcBtn").onclick=downloadCbc;$("passwordKeyBtn").onclick=passwordKey;
});
