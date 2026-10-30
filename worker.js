const COOKIE = "cafe_pos_session";
const SESSION_DAYS = 14;
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store",...headers}});
const html = (body, status=200) => new Response(body,{status,headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store"}});
const uid = () => crypto.randomUUID();
const now = () => new Date().toISOString();
const today = () => new Date().toISOString().slice(0,10);
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
async function hash(s){return hex(await crypto.subtle.digest("SHA-256",enc.encode(s)))}
async function passwordHash(password,salt=uid()){
 const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);
 const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:100000,hash:"SHA-256"},key,256);
 return `pbkdf2$${salt}$${hex(bits)}`;
}
async function verifyPassword(password,stored){const [alg,salt,want]=String(stored||"").split("$");if(alg!=="pbkdf2")return false;return (await passwordHash(password,salt)).split("$")[2]===want}
function cookieVal(req,name){const c=req.headers.get("Cookie")||"";for(const part of c.split(";")){const [k,...v]=part.trim().split("=");if(k===name)return decodeURIComponent(v.join("="))}return ""}
function setCookie(token,maxAge){return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`}
async function body(req){try{return await req.json()}catch{return {}}}
function safeNum(v,min=0){const n=Number(v);return Number.isFinite(n)&&n>=min?n:null}
const round = n => Math.round((Number(n)||0)*100)/100;
async function tableColumns(env,table){const rows=(await env.DB.prepare(`PRAGMA table_info("${table}")`).all()).results||[];return new Set(rows.map(x=>String(x.name)))}
async function tableExists(env,table){return !!(await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").bind(table).first())}
// Add optional fields required by the interface without dropping or recreating existing tables/data.
async function ensureCompatibility(env){
 let changed=false;
 const additions={
  restaurants:{tax_number:"TEXT NOT NULL DEFAULT ''",logo_url:"TEXT NOT NULL DEFAULT ''",tax_rate:"REAL NOT NULL DEFAULT 14",service_rate:"REAL NOT NULL DEFAULT 12",qr_target:"TEXT NOT NULL DEFAULT ''",show_invoice_qr:"INTEGER NOT NULL DEFAULT 1",invoice_design:"TEXT NOT NULL DEFAULT '{}'"},
  products:{active:"INTEGER NOT NULL DEFAULT 1",stock:"REAL NOT NULL DEFAULT 0"},
  invoices:{invoice_no:"INTEGER",date:"TEXT",business_name_snapshot:"TEXT NOT NULL DEFAULT ''",phone_snapshot:"TEXT NOT NULL DEFAULT ''",address_snapshot:"TEXT NOT NULL DEFAULT ''",tax_number_snapshot:"TEXT NOT NULL DEFAULT ''",logo_url_snapshot:"TEXT NOT NULL DEFAULT ''",table_no:"TEXT NOT NULL DEFAULT ''",cashier:"TEXT NOT NULL DEFAULT ''",order_type:"TEXT NOT NULL DEFAULT 'داخل المطعم'",taxable_base:"REAL NOT NULL DEFAULT 0",tax_rate:"REAL NOT NULL DEFAULT 14",tax_amount:"REAL NOT NULL DEFAULT 0",service_rate:"REAL NOT NULL DEFAULT 12",service_amount:"REAL NOT NULL DEFAULT 0",notes:"TEXT NOT NULL DEFAULT ''",created_by:"TEXT NOT NULL DEFAULT ''",invoice_design_snapshot:"TEXT NOT NULL DEFAULT '{}'"},
  invoice_items:{name_snapshot:"TEXT NOT NULL DEFAULT ''"},
  expenses:{date:"TEXT",payment_method:"TEXT NOT NULL DEFAULT 'نقدي'",created_by:"TEXT NOT NULL DEFAULT ''"},
  daily_closings:{expected_cash:"REAL NOT NULL DEFAULT 0",actual_cash:"REAL NOT NULL DEFAULT 0",cash_difference:"REAL NOT NULL DEFAULT 0",notes:"TEXT NOT NULL DEFAULT ''",closed_by:"TEXT NOT NULL DEFAULT ''",closed_at:"TEXT",invoice_count:"INTEGER NOT NULL DEFAULT 0",gross_subtotal:"REAL NOT NULL DEFAULT 0",discounts:"REAL NOT NULL DEFAULT 0",net_sales:"REAL NOT NULL DEFAULT 0",tax_total:"REAL NOT NULL DEFAULT 0",service_total:"REAL NOT NULL DEFAULT 0",cash_sales:"REAL NOT NULL DEFAULT 0",card_sales:"REAL NOT NULL DEFAULT 0",other_sales:"REAL NOT NULL DEFAULT 0",expenses_total:"REAL NOT NULL DEFAULT 0"}
 };
 for(const [table,fields] of Object.entries(additions)){
  if(!(await tableExists(env,table)))continue;
  let cols=await tableColumns(env,table);
  for(const [name,definition] of Object.entries(fields))if(!cols.has(name)){
   try{await env.DB.prepare(`ALTER TABLE "${table}" ADD COLUMN "${name}" ${definition}`).run();cols.add(name);changed=true}catch(e){if(!String(e).toLowerCase().includes("duplicate column"))throw e}
  }
 }
 // Backfill old records only once, when compatibility columns were added.
 if(changed){
  await env.DB.prepare("UPDATE invoices SET date=substr(created_at,1,10) WHERE date IS NULL OR date=''").run();
  await env.DB.prepare("UPDATE invoices SET invoice_no=invoice_number WHERE invoice_no IS NULL").run();
  await env.DB.prepare("UPDATE invoices SET taxable_base=MAX(0,subtotal-discount) WHERE taxable_base=0 AND subtotal>discount").run();
  await env.DB.prepare("UPDATE invoices SET tax_amount=tax WHERE tax_amount=0 AND tax<>0").run();
  await env.DB.prepare("UPDATE invoices SET service_amount=service WHERE service_amount=0 AND service<>0").run();
  await env.DB.prepare("UPDATE invoice_items SET name_snapshot=product_name WHERE name_snapshot=''").run();
  await env.DB.prepare("UPDATE expenses SET date=substr(created_at,1,10) WHERE date IS NULL OR date=''").run();
 }
}
async function userFrom(req,env){const token=cookieVal(req,COOKIE);if(!token)return null;const s=await env.DB.prepare("SELECT sessions.id AS sid, users.id, users.name, users.email, users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?").bind(await hash(token),now()).first();return s?{...s}:null}
async function context(req,env){
 const user=await userFrom(req,env);if(!user)return {error:json({error:"يجب تسجيل الدخول أولاً"},401)};
 const raw=await env.DB.prepare("SELECT * FROM restaurants WHERE owner_id=? ORDER BY created_at LIMIT 1").bind(user.id).first();
 if(!raw)return {error:json({error:"بيانات المطعم غير موجودة"},404)};
 const restaurant={...raw,tax_rate:raw.tax_rate??raw.tax_percent??14,service_rate:raw.service_rate??raw.service_percent??12,tax_number:raw.tax_number??"",logo_url:raw.logo_url??"",qr_target:raw.qr_target??"",phone:raw.phone??"",address:raw.address??"",currency:raw.currency??"EGP"};
 return {user,restaurant};
}
async function audit(env,r,u,action,type,id="",details="") {try{if(!(await tableExists(env,"audit_logs")))return;const cols=await tableColumns(env,"audit_logs"),values={id:uid(),restaurant_id:r.id,user_id:u.id,action,entity_type:type,entity_id:id,details:String(details).slice(0,2000),created_at:now()};const selected=Object.entries(values).filter(([k])=>cols.has(k));if(!selected.length)return;await env.DB.prepare(`INSERT INTO audit_logs(${selected.map(([k])=>`"${k}"`).join(",")}) VALUES(${selected.map(()=>"?").join(",")})`).bind(...selected.map(([,v])=>v)).run()}catch(e){console.warn("Audit write skipped",String(e))}}
function invoiceSelect(){return `SELECT i.*, COALESCE(i.invoice_no,i.invoice_number) AS invoice_no, COALESCE(i.date,substr(i.created_at,1,10)) AS date, COALESCE(i.tax_amount,i.tax,0) AS tax_amount, COALESCE(i.service_amount,i.service,0) AS service_amount FROM invoices i`}
function csvCell(v){return '"'+String(v??"").replace(/"/g,'""')+'"'}
async function route(req,env){
 const url=new URL(req.url),p=url.pathname,method=req.method;
 if(p==="/"&&method==="GET"){try{const a=await env.ASSETS.fetch(req);return a}catch{return html("<h1>Cashier Pro</h1><p>Static assets are not configured.</p>")}}
 if(p==="/api/health")return json({ok:true,service:"cashier-pro",database:!!env.DB});
 // QR destination: return the receipt as a standalone SVG image, not an editable HTML page.
 // The image contains a read-only snapshot and exposes no application controls or write API.
 const publicInvoiceMatch=p.match(/^\/i\/([0-9a-f-]+)$/i);
 if(publicInvoiceMatch&&method==="GET"){
  await ensureCompatibility(env);
  const inv=await env.DB.prepare(`SELECT i.*,r.name AS restaurant_name,r.phone AS restaurant_phone,r.address AS restaurant_address,r.tax_number AS restaurant_tax_number,r.logo_url AS restaurant_logo_url,COALESCE(i.invoice_no,i.invoice_number) AS invoice_no,COALESCE(i.date,substr(i.created_at,1,10)) AS date,COALESCE(i.tax_amount,i.tax,0) AS tax_amount,COALESCE(i.service_amount,i.service,0) AS service_amount FROM invoices i JOIN restaurants r ON r.id=i.restaurant_id WHERE i.id=?`).bind(publicInvoiceMatch[1]).first();
  if(!inv)return new Response('الفاتورة غير موجودة أو لم تعد متاحة.',{status:404,headers:{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'}});
  const items=(await env.DB.prepare("SELECT *,COALESCE(name_snapshot,product_name) AS name_snapshot FROM invoice_items WHERE invoice_id=?").bind(inv.id).all()).results||[];
  const escSvg=v=>String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&apos;'}[c]));
  const fmt=v=>Number(v||0).toLocaleString('en-US',{minimumFractionDigits:2,maximumFractionDigits:2});
  const rowH=58, tableY=290, rowsEnd=tableY+58+items.length*rowH, totalsY=rowsEnd+32, footerY=totalsY+300, H=footerY+100;
  const name=inv.business_name_snapshot||inv.restaurant_name||'المطعم',logo=inv.logo_url_snapshot||inv.restaurant_logo_url||'';
  const texts=[];
  const txt=(x,y,value,size=24,weight=400,anchor='end',fill='#172334')=>texts.push(`<text x="${x}" y="${y}" font-family="Tahoma,Arial,sans-serif" font-size="${size}" font-weight="${weight}" text-anchor="${anchor}" fill="${fill}">${escSvg(value)}</text>`);
  const line=(y,x1=55,x2=845,stroke='#aab2bf',sw=2)=>texts.push(`<line x1="${x1}" y1="${y}" x2="${x2}" y2="${y}" stroke="${stroke}" stroke-width="${sw}"/>`);
  texts.push(`<rect x="1" y="1" width="898" height="${H-2}" rx="12" fill="#fff" stroke="#d8dee8" stroke-width="2"/>`);
  if(logo)texts.push(`<image href="${escSvg(logo)}" x="350" y="22" width="200" height="100" preserveAspectRatio="xMidYMid meet"/>`);
  txt(450,logo?155:85,name,38,800,'middle','#14243a');
  if(inv.phone_snapshot||inv.restaurant_phone)txt(450,logo?190:120,inv.phone_snapshot||inv.restaurant_phone,20,400,'middle','#475467');
  line(logo?215:145,55,845,'#9aa4b2',3);
  txt(845,logo?255:185,`رقم الفاتورة: ${inv.invoice_no}`,21,700);
  txt(470,logo?255:185,`التاريخ: ${inv.date||''}`,21);
  txt(845,logo?290:220,`الطاولة: ${inv.table_no||'—'}`,20);
  txt(470,logo?290:220,`الكاشير: ${inv.cashier||'—'}`,20);
  const ty=tableY;
  texts.push(`<rect x="55" y="${ty-38}" width="790" height="52" fill="#f0f3f7" stroke="#667085" stroke-width="2"/>`);
  txt(825,ty-4,'الصنف',21,700);txt(590,ty-4,'السعر',21,700);txt(390,ty-4,'الكمية',21,700);txt(180,ty-4,'الإجمالي',21,700);
  items.forEach((it,i)=>{let y=ty+58+i*rowH;texts.push(`<rect x="55" y="${y-42}" width="790" height="${rowH}" fill="#fff" stroke="#c8ced8" stroke-width="1"/>`);txt(825,y-7,it.name_snapshot||it.product_name,19);txt(590,y-7,fmt(it.unit_price),19);txt(390,y-7,it.quantity,19);txt(180,y-7,fmt(it.line_total),19);});
  const totals=[['المجموع',fmt(inv.subtotal)],['الخصم',fmt(inv.discount)],['الضريبة',fmt(inv.tax_amount??inv.tax)],['الخدمة',fmt(inv.service_amount??inv.service)]];
  totals.forEach((a,i)=>txt(845,totalsY+i*38,`${a[0]}: ${a[1]}`,21));
  line(totalsY+165,430,845,'#14243a',3);txt(845,totalsY+210,`الإجمالي: ${fmt(inv.total)}`,30,800,'end','#14243a');
  if(inv.notes)txt(845,totalsY+250,`ملاحظات: ${inv.notes}`,18);
  let fy=footerY;if(inv.tax_number_snapshot||inv.restaurant_tax_number)txt(450,fy,`الرقم الضريبي: ${inv.tax_number_snapshot||inv.restaurant_tax_number}`,17,400,'middle','#475467');
  if(inv.address_snapshot||inv.restaurant_address)txt(450,fy+32,`العنوان: ${inv.address_snapshot||inv.restaurant_address}`,17,400,'middle','#475467');
  txt(450,H-28,'شكرًا لزيارتكم',22,700,'middle','#14243a');
  const svg=`<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="900" height="${H}" viewBox="0 0 900 ${H}">${texts.join('')}</svg>`;
  return new Response(svg,{headers:{'content-type':'image/svg+xml; charset=utf-8','cache-control':'no-store, private','x-content-type-options':'nosniff','content-disposition':'inline; filename="receipt.svg"'}});
 }

 if(p==="/api/auth/register"&&method==="POST"){
  const b=await body(req),name=String(b.name||"").trim(),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||"");
  if(name.length<2||!email.includes("@")||password.length<10)return json({error:"أدخل الاسم والبريد وكلمة مرور لا تقل عن 10 أحرف"},400);
  if(await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first())return json({error:"البريد الإلكتروني مسجل بالفعل"},409);
  const id=uid();await env.DB.prepare("INSERT INTO users(id,name,email,password_hash,role) VALUES(?,?,?,?,?)").bind(id,name,email,await passwordHash(password),"admin").run();
  const rid=uid(),restaurantName=String(b.restaurantName||"مطعمي / الكافيه").trim()||"مطعمي / الكافيه",cols=await tableColumns(env,"restaurants");
  const vals={id:rid,owner_id:id,name:restaurantName,phone:"",address:"",tax_number:"",logo_url:"",currency:"EGP",tax_rate:14,service_rate:12,tax_percent:14,service_percent:12,qr_target:""},fields=Object.entries(vals).filter(([k])=>cols.has(k));
  await env.DB.prepare(`INSERT INTO restaurants(${fields.map(([k])=>`"${k}"`).join(",")}) VALUES(${fields.map(()=>"?").join(",")})`).bind(...fields.map(([,v])=>v)).run();
  const token=uid()+uid(),expires=new Date(Date.now()+SESSION_DAYS*86400000).toISOString();await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)").bind(uid(),id,await hash(token),expires).run();
  return json({ok:true,user:{id,name,email}},201,{"set-cookie":setCookie(token,SESSION_DAYS*86400)});
 }
 if(p==="/api/auth/login"&&method==="POST"){
  const b=await body(req),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||""),u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
  if(!u||!(await verifyPassword(password,u.password_hash)))return json({error:"البريد الإلكتروني أو كلمة المرور غير صحيحة"},401);
  const token=uid()+uid(),expires=new Date(Date.now()+SESSION_DAYS*86400000).toISOString();await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)").bind(uid(),u.id,await hash(token),expires).run();
  return json({ok:true,user:{id:u.id,name:u.name,email:u.email,role:u.role}},200,{"set-cookie":setCookie(token,SESSION_DAYS*86400)});
 }
 if(p==="/api/auth/logout"&&method==="POST"){const token=cookieVal(req,COOKIE);if(token)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await hash(token)).run();return json({ok:true},200,{"set-cookie":`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`})}
 if(p.startsWith("/api/")&&p!=="/api/health")await ensureCompatibility(env);
 const c=await context(req,env);if(c.error)return c.error;const {user,restaurant:r}=c;
 if(p==="/api/me"&&method==="GET")return json({user:{id:user.id,name:user.name,email:user.email,role:user.role},restaurant:r});
 if(p==="/api/invoice-design"&&method==="PUT"){
  const b=await body(req),raw=String(b.invoice_design||"{}");if(raw.length>30000)return json({error:"حجم بيانات القوالب كبير جدًا"},413);let parsed;try{parsed=JSON.parse(raw)}catch{return json({error:"بيانات القوالب غير صحيحة"},400)}if(!parsed||!Array.isArray(parsed.themes)||parsed.themes.length<1||parsed.themes.length>30)return json({error:"يجب حفظ قالب واحد على الأقل وبحد أقصى 30 قالبًا"},400);
  const cols=await tableColumns(env,"restaurants");if(!cols.has("invoice_design"))return json({error:"قاعدة البيانات لم تُحدّث بعد؛ أعد تحميل الصفحة وحاول مرة أخرى"},500);await env.DB.prepare("UPDATE restaurants SET invoice_design=? WHERE id=?").bind(JSON.stringify(parsed),r.id).run();r.invoice_design=JSON.stringify(parsed);await audit(env,r,user,"update","invoice_theme",r.id,"حفظ قوالب الفاتورة");return json({ok:true,invoice_design:r.invoice_design});
 }
 if(p==="/api/settings"&&method==="PUT"){
  const b=await body(req),name=String(b.name||"").trim(),tax=safeNum(b.tax_rate),service=safeNum(b.service_rate);if(name.length<2)return json({error:"اسم المطعم مطلوب"},400);if(tax===null||service===null||tax>100||service>100)return json({error:"نسب الضريبة والخدمة يجب أن تكون بين 0 و100"},400);
  const cols=await tableColumns(env,"restaurants"),vals={name,phone:String(b.phone||""),address:String(b.address||""),tax_number:String(b.tax_number||""),logo_url:String(b.logo_url||""),currency:String(b.currency||"EGP"),tax_rate:tax,service_rate:service,tax_percent:tax,service_percent:service,qr_target:String(b.qr_target||""),show_invoice_qr:b.show_invoice_qr===false||b.show_invoice_qr===0?0:1,invoice_design:String(b.invoice_design||r.invoice_design||'{}').slice(0,30000)},selected=Object.entries(vals).filter(([k])=>cols.has(k));
  await env.DB.prepare(`UPDATE restaurants SET ${selected.map(([k])=>`"${k}"=?`).join(",")} WHERE id=?`).bind(...selected.map(([,v])=>v),r.id).run();await audit(env,r,user,"update","settings",r.id,"تحديث إعدادات المطعم");return json({ok:true});
 }
 if(p==="/api/products"&&method==="GET")return json({products:(await env.DB.prepare("SELECT * FROM products WHERE restaurant_id=? ORDER BY active DESC,name").bind(r.id).all()).results});
 if(p==="/api/products"&&method==="POST"){
  const b=await body(req),name=String(b.name||"").trim(),price=safeNum(b.price);if(!name||price===null)return json({error:"اسم الصنف والسعر مطلوبان"},400);const id=uid();await env.DB.prepare("INSERT INTO products(id,restaurant_id,name,category,price,active) VALUES(?,?,?,?,?,1)").bind(id,r.id,name,String(b.category||""),price).run();await audit(env,r,user,"create","product",id,name);return json({ok:true,id},201);
 }
 const prodMatch=p.match(/^\/api\/products\/([0-9a-f-]+)$/i);if(prodMatch&&method==="DELETE"){await env.DB.prepare("UPDATE products SET active=0 WHERE id=? AND restaurant_id=?").bind(prodMatch[1],r.id).run();await audit(env,r,user,"archive","product",prodMatch[1]);return json({ok:true})}
 if(p==="/api/invoices"&&method==="GET"){
  const from=url.searchParams.get("from")||"0000-01-01",to=url.searchParams.get("to")||"9999-12-31",rows=(await env.DB.prepare(`${invoiceSelect()} WHERE i.restaurant_id=? AND COALESCE(i.date,substr(i.created_at,1,10))>=? AND COALESCE(i.date,substr(i.created_at,1,10))<=? ORDER BY i.created_at DESC LIMIT 2000`).bind(r.id,from,to).all()).results;return json({invoices:rows});
 }
 if(p==="/api/invoices"&&method==="POST"){
  const b=await body(req),items=Array.isArray(b.items)?b.items:[];if(!items.length)return json({error:"أضف صنفًا واحدًا على الأقل"},400);
  const clean=[];for(const x of items){const name=String(x.name||"").trim(),price=safeNum(x.price),qty=safeNum(x.quantity,0.01);if(!name||price===null||qty===null||qty<=0)return json({error:"بيانات صنف غير صحيحة"},400);clean.push({id:uid(),product_id:x.product_id||null,name,price,qty,line:round(price*qty)})}
  const subtotal=round(clean.reduce((a,x)=>a+x.line,0)),discount=safeNum(b.discount??0);if(discount===null||discount>subtotal)return json({error:"الخصم غير صحيح"},400);
  const taxRate=b.tax_rate===undefined?r.tax_rate:safeNum(b.tax_rate),serviceRate=b.service_rate===undefined?r.service_rate:safeNum(b.service_rate);if(taxRate===null||serviceRate===null||taxRate>100||serviceRate>100)return json({error:"نسبة ضريبة أو خدمة غير صحيحة"},400);
  const base=round(subtotal-discount),tax=round(base*taxRate/100),service=round(base*serviceRate/100),total=round(base+tax+service),seq=await env.DB.prepare("SELECT COALESCE(MAX(invoice_number),0)+1 AS n FROM invoices WHERE restaurant_id=?").bind(r.id).first(),num=seq.n,id=uid(),created=now(),date=created.slice(0,10),payment=String(b.payment_method||"نقدي"),allowed=["نقدي","فيزا / بطاقة","محفظة إلكترونية","آجل"];
  if(!allowed.includes(payment))return json({error:"طريقة الدفع غير صحيحة"},400);
  const invCols=await tableColumns(env,"invoices"),invVals={id,restaurant_id:r.id,invoice_number:num,invoice_no:num,subtotal,discount,tax,service,total,payment_method:payment,status:payment==="آجل"?"unpaid":"paid",created_at:created,date,business_name_snapshot:r.name,phone_snapshot:r.phone,address_snapshot:r.address,tax_number_snapshot:r.tax_number,logo_url_snapshot:r.logo_url,invoice_design_snapshot:String(r.invoice_design||'{}'),table_no:String(b.table_no||""),cashier:String(b.cashier||""),order_type:String(b.order_type||"داخل المطعم"),taxable_base:base,tax_rate:taxRate,tax_amount:tax,service_rate:serviceRate,service_amount:service,notes:String(b.notes||""),created_by:user.id},invFields=Object.entries(invVals).filter(([k])=>invCols.has(k));
  const stmts=[env.DB.prepare(`INSERT INTO invoices(${invFields.map(([k])=>`"${k}"`).join(",")}) VALUES(${invFields.map(()=>"?").join(",")})`).bind(...invFields.map(([,v])=>v))];
  const itemCols=await tableColumns(env,"invoice_items");for(const x of clean){const vals={id:x.id,invoice_id:id,product_id:x.product_id,product_name:x.name,name_snapshot:x.name,unit_price:x.price,quantity:x.qty,line_total:x.line},fields=Object.entries(vals).filter(([k])=>itemCols.has(k));stmts.push(env.DB.prepare(`INSERT INTO invoice_items(${fields.map(([k])=>`"${k}"`).join(",")}) VALUES(${fields.map(()=>"?").join(",")})`).bind(...fields.map(([,v])=>v)))}
  await env.DB.batch(stmts);await audit(env,r,user,"create","invoice",id,`فاتورة ${num} بإجمالي ${total}`);return json({ok:true,id,invoice_no:num,subtotal,discount,tax_rate:taxRate,tax_amount:tax,service_rate:serviceRate,service_amount:service,total},201);
 }
 const invMatch=p.match(/^\/api\/invoices\/([0-9a-f-]+)$/i);if(invMatch&&method==="GET"){
  const inv=await env.DB.prepare(`${invoiceSelect()} WHERE i.id=? AND i.restaurant_id=?`).bind(invMatch[1],r.id).first();if(!inv)return json({error:"الفاتورة غير موجودة"},404);
  inv.business_name_snapshot=inv.business_name_snapshot||r.name;inv.phone_snapshot=inv.phone_snapshot||r.phone;inv.address_snapshot=inv.address_snapshot||r.address;inv.tax_number_snapshot=inv.tax_number_snapshot||r.tax_number;inv.logo_url_snapshot=inv.logo_url_snapshot||r.logo_url;inv.tax_rate=inv.tax_rate??r.tax_rate;inv.service_rate=inv.service_rate??r.service_rate;
  const items=(await env.DB.prepare("SELECT *,COALESCE(name_snapshot,product_name) AS name_snapshot FROM invoice_items WHERE invoice_id=?").bind(inv.id).all()).results;return json({invoice:inv,items,qr_data:`${inv.business_name_snapshot}|${inv.invoice_no}|${Number(inv.total||0).toFixed(2)}`});
 }
 if(p==="/api/expenses"&&method==="GET")return json({expenses:(await env.DB.prepare("SELECT * FROM expenses WHERE restaurant_id=? ORDER BY date DESC,created_at DESC LIMIT 2000").bind(r.id).all()).results});
 if(p==="/api/expenses"&&method==="POST"){
  const b=await body(req),amount=safeNum(b.amount),category=String(b.category||"").trim();if(amount===null||amount<=0||!category)return json({error:"أدخل قيمة المصروف وتصنيفه"},400);const id=uid(),cols=await tableColumns(env,"expenses"),vals={id,restaurant_id:r.id,date:String(b.date||today()),amount,category,description:String(b.description||""),payment_method:String(b.payment_method||"نقدي"),created_by:user.id,created_at:now()},fields=Object.entries(vals).filter(([k])=>cols.has(k));await env.DB.prepare(`INSERT INTO expenses(${fields.map(([k])=>`"${k}"`).join(",")}) VALUES(${fields.map(()=>"?").join(",")})`).bind(...fields.map(([,v])=>v)).run();await audit(env,r,user,"create","expense",id,`${amount}`);return json({ok:true,id},201);
 }
 if(p==="/api/closing"&&method==="POST"){
  const b=await body(req),date=String(b.date||today()),already=await env.DB.prepare("SELECT id FROM daily_closings WHERE restaurant_id=? AND closing_date=?").bind(r.id,date).first();if(already)return json({error:"تم إغلاق هذا اليوم بالفعل. راجع سجل الإغلاقات."},409);
  const s=await env.DB.prepare(`SELECT COUNT(*) invoice_count,COALESCE(SUM(subtotal),0) gross_subtotal,COALESCE(SUM(discount),0) discounts,COALESCE(SUM(taxable_base),0) net_sales,COALESCE(SUM(tax_amount),0) tax_total,COALESCE(SUM(service_amount),0) service_total,COALESCE(SUM(CASE WHEN payment_method='نقدي' THEN total ELSE 0 END),0) cash_sales,COALESCE(SUM(CASE WHEN payment_method='فيزا / بطاقة' THEN total ELSE 0 END),0) card_sales,COALESCE(SUM(CASE WHEN payment_method NOT IN ('نقدي','فيزا / بطاقة') THEN total ELSE 0 END),0) other_sales FROM invoices WHERE restaurant_id=? AND COALESCE(date,substr(created_at,1,10))=?`).bind(r.id,date).first();
  const ex=await env.DB.prepare("SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE restaurant_id=? AND date=? AND payment_method='نقدي'").bind(r.id,date).first(),actual=safeNum(b.actual_cash);if(actual===null)return json({error:"أدخل النقدية الفعلية"},400);const expected=round(s.cash_sales-ex.n),id=uid(),closed=now(),diff=round(actual-expected);
  await env.DB.prepare("INSERT INTO daily_closings(id,restaurant_id,closing_date,total_sales,total_expenses,cash_total,card_total,expected_cash,actual_cash,cash_difference,notes,closed_by,closed_at,invoice_count,gross_subtotal,discounts,net_sales,tax_total,service_total,cash_sales,card_sales,other_sales,expenses_total) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id,r.id,date,round(s.cash_sales+s.card_sales+s.other_sales),ex.n,s.cash_sales,s.card_sales,expected,actual,diff,String(b.notes||""),user.id,closed,s.invoice_count,s.gross_subtotal,s.discounts,s.net_sales,s.tax_total,s.service_total,s.cash_sales,s.card_sales,s.other_sales,ex.n).run();await audit(env,r,user,"close","day",id,date);return json({ok:true,closing:{id,date,business_date:date,...s,expenses_total:ex.n,expected_cash:expected,actual_cash:actual,cash_difference:diff,notes:String(b.notes||""),closed_at:closed}},201);
 }
 if(p==="/api/closing"&&method==="GET"){
  const rows=(await env.DB.prepare("SELECT *,closing_date AS business_date FROM daily_closings WHERE restaurant_id=? ORDER BY closing_date DESC LIMIT 500").bind(r.id).all()).results;return json({closings:rows});
 }
 if(p==="/api/reports"&&method==="GET"){
  const from=url.searchParams.get("from")||today(),to=url.searchParams.get("to")||today();const sales=await env.DB.prepare(`SELECT COALESCE(date,substr(created_at,1,10)) AS date,COUNT(*) invoice_count,COALESCE(SUM(subtotal),0) subtotal,COALESCE(SUM(discount),0) discounts,COALESCE(SUM(tax_amount),SUM(tax),0) tax,COALESCE(SUM(service_amount),SUM(service),0) service,COALESCE(SUM(total),0) total,SUM(CASE WHEN payment_method='نقدي' THEN total ELSE 0 END) cash,SUM(CASE WHEN payment_method='فيزا / بطاقة' THEN total ELSE 0 END) card FROM invoices WHERE restaurant_id=? AND COALESCE(date,substr(created_at,1,10))>=? AND COALESCE(date,substr(created_at,1,10))<=? GROUP BY COALESCE(date,substr(created_at,1,10)) ORDER BY date DESC`).bind(r.id,from,to).all();
  const expenses=await env.DB.prepare("SELECT date,SUM(amount) total FROM expenses WHERE restaurant_id=? AND date>=? AND date<=? GROUP BY date ORDER BY date DESC").bind(r.id,from,to).all();return json({sales:sales.results,expenses:expenses.results,from,to});
 }
 if(p==="/api/export.csv"&&method==="GET"){
  const from=url.searchParams.get("from")||today(),to=url.searchParams.get("to")||today(),rows=(await env.DB.prepare(`${invoiceSelect()} WHERE i.restaurant_id=? AND COALESCE(i.date,substr(i.created_at,1,10))>=? AND COALESCE(i.date,substr(i.created_at,1,10))<=? ORDER BY i.created_at`).bind(r.id,from,to).all()).results;
  const lines=[["رقم الفاتورة","التاريخ","وقت الإنشاء","الكاشير","الطاولة","طريقة الدفع","قبل الخصم","الخصم","نسبة الضريبة","الضريبة","نسبة الخدمة","الخدمة","الإجمالي","الحالة"],...rows.map(x=>[x.invoice_no,x.date,x.created_at,x.cashier,x.table_no,x.payment_method,x.subtotal,x.discount,x.tax_rate,x.tax_amount,x.service_rate,x.service_amount,x.total,x.status])];return new Response("\ufeff"+lines.map(row=>row.map(csvCell).join(",")).join("\r\n"),{headers:{"content-type":"text/csv; charset=utf-8","content-disposition":`attachment; filename="sales-${from}-${to}.csv"`}});
 }
 if(p==="/api/audit"&&method==="GET"){
  if(!(await tableExists(env,"audit_logs")))return json({logs:[]});const rows=(await env.DB.prepare("SELECT action,entity_type,entity_id,details,created_at FROM audit_logs WHERE restaurant_id=? ORDER BY created_at DESC LIMIT 500").bind(r.id).all()).results;return json({logs:rows});
 }
 return json({error:"المسار غير موجود"},404);
}
export default {async fetch(req,env){try{return await route(req,env)}catch(e){console.error("Cashier Pro request failed:",{path:new URL(req.url).pathname,method:req.method,error:String(e?.stack||e)});return json({error:"حدث خطأ في الخادم",request_id:req.headers.get("cf-ray")||"unknown"},500)}}};
