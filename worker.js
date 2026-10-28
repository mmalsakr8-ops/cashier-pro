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
async function verifyPassword(password,stored){
  const [alg,salt,want]=String(stored).split("$"); if(alg!=="pbkdf2") return false;
  return (await passwordHash(password,salt)).split("$")[2]===want;
}
function cookieVal(req,name){const c=req.headers.get("Cookie")||"";for(const part of c.split(";")){const [k,...v]=part.trim().split("=");if(k===name)return decodeURIComponent(v.join("="))}return ""}
function setCookie(token, maxAge){return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`}
async function body(req){try{return await req.json()}catch{return {}}}
function safeNum(v,min=0){const n=Number(v);return Number.isFinite(n)&&n>=min?n:null}
async function userFrom(req,env){
  const token=cookieVal(req,COOKIE);if(!token)return null;
  const s=await env.DB.prepare("SELECT sessions.id AS sid, users.id, users.name, users.email, users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?").bind(await hash(token),now()).first();
  return s?{...s}:null;
}
async function context(req,env){
  const user=await userFrom(req,env);if(!user)return {error:json({error:"يجب تسجيل الدخول أولاً"},401)};
  const restaurant=await env.DB.prepare("SELECT * FROM restaurants WHERE owner_id=?").bind(user.id).first();
  if(!restaurant)return {error:json({error:"بيانات المطعم غير موجودة"},404)};
  return {user,restaurant};
}
async function audit(env,r,u,action,type,id="",details=""){
  await env.DB.prepare("INSERT INTO audit_logs(id,restaurant_id,user_id,action,entity_type,entity_id,details) VALUES(?,?,?,?,?,?,?)")
    .bind(uid(),r.id,u.id,action,type,id,String(details).slice(0,2000)).run();
}
function csvCell(v){return '"'+String(v??"").replace(/"/g,'""')+'"'}
async function route(req,env){
 const url=new URL(req.url),p=url.pathname,method=req.method;
 if(p==="/"&&method==="GET")return html(await env.ASSETS?.fetch(req).then(r=>r.text()).catch(()=>null) || "<h1>Restaurant POS</h1><p>Upload the public folder to the configured static assets binding.</p>");
 if(p==="/api/health")return json({ok:true,service:"restaurant-cafe-pos",database:!!env.DB});
 if(p==="/api/auth/register"&&method==="POST"){
   const b=await body(req),name=String(b.name||"").trim(),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||"");
   if(name.length<2||!email.includes("@")||password.length<10)return json({error:"أدخل الاسم والبريد وكلمة مرور لا تقل عن 10 أحرف"},400);
   const existing=await env.DB.prepare("SELECT id FROM users WHERE email=?").bind(email).first();if(existing)return json({error:"البريد الإلكتروني مسجل بالفعل"},409);
   const id=uid();await env.DB.prepare("INSERT INTO users(id,name,email,password_hash,role) VALUES(?,?,?,?,?)").bind(id,name,email,await passwordHash(password),"admin").run();
   const rid=uid();await env.DB.prepare("INSERT INTO restaurants(id,owner_id,name) VALUES(?,?,?)").bind(rid,id,String(b.restaurantName||"مطعمي / كافيهي").trim()).run();
   const token=uid()+uid(),expires=new Date(Date.now()+SESSION_DAYS*86400000).toISOString();
   await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)").bind(uid(),id,await hash(token),expires).run();
   return json({ok:true,user:{id,name,email}},201,{"set-cookie":setCookie(token,SESSION_DAYS*86400)});
 }
 if(p==="/api/auth/login"&&method==="POST"){
   const b=await body(req),email=String(b.email||"").trim().toLowerCase(),password=String(b.password||"");
   const u=await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
   if(!u||!(await verifyPassword(password,u.password_hash)))return json({error:"البريد الإلكتروني أو كلمة المرور غير صحيحة"},401);
   const token=uid()+uid(),expires=new Date(Date.now()+SESSION_DAYS*86400000).toISOString();
   await env.DB.prepare("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)").bind(uid(),u.id,await hash(token),expires).run();
   return json({ok:true,user:{id:u.id,name:u.name,email:u.email,role:u.role}},200,{"set-cookie":setCookie(token,SESSION_DAYS*86400)});
 }
 if(p==="/api/auth/logout"&&method==="POST"){
   const token=cookieVal(req,COOKIE);if(token)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await hash(token)).run();
   return json({ok:true},200,{"set-cookie":`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`});
 }
 const c=await context(req,env);if(c.error)return c.error;const {user,restaurant:r}=c;
 if(p==="/api/me"&&method==="GET")return json({user:{id:user.id,name:user.name,email:user.email,role:user.role},restaurant:r});
 if(p==="/api/settings"&&method==="PUT"){
   const b=await body(req),name=String(b.name||"").trim();if(name.length<2)return json({error:"اسم المطعم مطلوب"},400);
   const tax=safeNum(b.tax_rate),service=safeNum(b.service_rate);if(tax===null||service===null||tax>100||service>100)return json({error:"نسب الضريبة والخدمة يجب أن تكون بين 0 و100"},400);
   await env.DB.prepare("UPDATE restaurants SET name=?,phone=?,address=?,tax_number=?,logo_url=?,currency=?,tax_rate=?,service_rate=?,qr_target=? WHERE id=?")
    .bind(name,String(b.phone||""),String(b.address||""),String(b.tax_number||""),String(b.logo_url||""),String(b.currency||"EGP"),tax,service,String(b.qr_target||""),r.id).run();
   await audit(env,r,user,"update","settings",r.id,"تحديث إعدادات المطعم");return json({ok:true});
 }
 if(p==="/api/products"&&method==="GET")return json({products:(await env.DB.prepare("SELECT * FROM products WHERE restaurant_id=? ORDER BY name").bind(r.id).all()).results});
 if(p==="/api/products"&&method==="POST"){
   const b=await body(req),name=String(b.name||"").trim(),price=safeNum(b.price);if(!name||price===null)return json({error:"اسم الصنف والسعر مطلوبان"},400);
   const id=uid();await env.DB.prepare("INSERT INTO products(id,restaurant_id,name,category,price) VALUES(?,?,?,?,?)").bind(id,r.id,name,String(b.category||""),price).run();
   await audit(env,r,user,"create","product",id,name);return json({ok:true,id},201);
 }
 const prodMatch=p.match(/^\/api\/products\/([0-9a-f-]+)$/);
 if(prodMatch&&method==="DELETE"){await env.DB.prepare("UPDATE products SET active=0 WHERE id=? AND restaurant_id=?").bind(prodMatch[1],r.id).run();await audit(env,r,user,"archive","product",prodMatch[1]);return json({ok:true})}
 if(p==="/api/invoices"&&method==="GET"){
   const from=url.searchParams.get("from")||"0000-01-01",to=url.searchParams.get("to")||"9999-12-31";
   const rows=(await env.DB.prepare("SELECT * FROM invoices WHERE restaurant_id=? AND date>=? AND date<=? ORDER BY created_at DESC LIMIT 2000").bind(r.id,from,to).all()).results;
   return json({invoices:rows});
 }
 if(p==="/api/invoices"&&method==="POST"){
   const b=await body(req),items=Array.isArray(b.items)?b.items:[];if(!items.length)return json({error:"أضف صنفًا واحدًا على الأقل"},400);
   const clean=[];for(const x of items){const name=String(x.name||"").trim(),price=safeNum(x.price),qty=safeNum(x.quantity,0.01);if(!name||price===null||qty===null||qty<=0)return json({error:"بيانات صنف غير صحيحة"},400);clean.push({id:uid(),product_id:x.product_id||null,name,price,qty,line:Math.round(price*qty*100)/100})}
   const subtotal=Math.round(clean.reduce((a,x)=>a+x.line,0)*100)/100,discount=safeNum(b.discount||0);if(discount===null||discount>subtotal)return json({error:"الخصم غير صحيح"},400);
   const taxRate=b.tax_rate===undefined?r.tax_rate:safeNum(b.tax_rate),serviceRate=b.service_rate===undefined?r.service_rate:safeNum(b.service_rate);
   if(taxRate===null||serviceRate===null||taxRate>100||serviceRate>100)return json({error:"نسبة ضريبة أو خدمة غير صحيحة"},400);
   const base=Math.round((subtotal-discount)*100)/100,tax=Math.round(base*taxRate)/100,service=Math.round(base*serviceRate)/100,total=Math.round((base+tax+service)*100)/100;
   const seq=await env.DB.prepare("SELECT COALESCE(MAX(invoice_no),0)+1 AS n FROM invoices WHERE restaurant_id=?").bind(r.id).first(),num=seq.n,id=uid(),created=now(),date=created.slice(0,10);
   const payment=String(b.payment_method||"نقدي"),allowed=["نقدي","فيزا / بطاقة","محفظة إلكترونية","آجل"];if(!allowed.includes(payment))return json({error:"طريقة الدفع غير صحيحة"},400);
   await env.DB.batch([
    env.DB.prepare(`INSERT INTO invoices(id,restaurant_id,invoice_no,business_name_snapshot,phone_snapshot,address_snapshot,tax_number_snapshot,date,created_at,table_no,cashier,order_type,payment_method,status,subtotal,discount,taxable_base,tax_rate,tax_amount,service_rate,service_amount,total,notes,created_by)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,r.id,num,r.name,r.phone,r.address,r.tax_number,date,created,String(b.table_no||""),String(b.cashier||""),String(b.order_type||"داخل المطعم"),payment,payment==="آجل"?"unpaid":"paid",subtotal,discount,base,taxRate,tax,serviceRate,service,total,String(b.notes||""),user.id),
    ...clean.map(x=>env.DB.prepare("INSERT INTO invoice_items(id,invoice_id,product_id,name_snapshot,unit_price,quantity,line_total) VALUES(?,?,?,?,?,?,?)").bind(x.id,id,x.product_id,x.name,x.price,x.qty,x.line))
   ]);
   await audit(env,r,user,"create","invoice",id,`فاتورة ${num} بإجمالي ${total}`);
   return json({ok:true,id,invoice_no:num,subtotal,discount,tax_rate:taxRate,tax_amount:tax,service_rate:serviceRate,service_amount:service,total},201);
 }
 const invMatch=p.match(/^\/api\/invoices\/([0-9a-f-]+)$/);
 if(invMatch&&method==="GET"){
   const inv=await env.DB.prepare("SELECT * FROM invoices WHERE id=? AND restaurant_id=?").bind(invMatch[1],r.id).first();if(!inv)return json({error:"الفاتورة غير موجودة"},404);
   const items=(await env.DB.prepare("SELECT * FROM invoice_items WHERE invoice_id=?").bind(inv.id).all()).results;return json({invoice:inv,items,qr_data:`${inv.business_name_snapshot}|${inv.invoice_no}|${inv.total.toFixed(2)}`});
 }
 if(p==="/api/expenses"&&method==="GET")return json({expenses:(await env.DB.prepare("SELECT * FROM expenses WHERE restaurant_id=? ORDER BY date DESC,created_at DESC LIMIT 2000").bind(r.id).all()).results});
 if(p==="/api/expenses"&&method==="POST"){
   const b=await body(req),amount=safeNum(b.amount);if(amount===null||amount<=0||!String(b.category||"").trim())return json({error:"أدخل قيمة المصروف وتصنيفه"},400);
   const id=uid();await env.DB.prepare("INSERT INTO expenses(id,restaurant_id,date,amount,category,description,payment_method,created_by) VALUES(?,?,?,?,?,?,?,?)").bind(id,r.id,String(b.date||today()),amount,String(b.category),String(b.description||""),String(b.payment_method||"نقدي"),user.id).run();
   await audit(env,r,user,"create","expense",id,`${amount}`);return json({ok:true,id},201);
 }
 if(p==="/api/closing"&&method==="POST"){
   const b=await body(req),date=String(b.date||today()),already=await env.DB.prepare("SELECT id FROM closings WHERE restaurant_id=? AND business_date=? AND status='closed'").bind(r.id,date).first();if(already)return json({error:"تم إغلاق هذا اليوم بالفعل. راجع سجل الإغلاقات."},409);
   const s=await env.DB.prepare(`SELECT COUNT(*) invoice_count,COALESCE(SUM(subtotal),0) gross_subtotal,COALESCE(SUM(discount),0) discounts,COALESCE(SUM(taxable_base),0) net_sales,COALESCE(SUM(tax_amount),0) tax_total,COALESCE(SUM(service_amount),0) service_total,COALESCE(SUM(CASE WHEN payment_method='نقدي' THEN total ELSE 0 END),0) cash_sales,COALESCE(SUM(CASE WHEN payment_method='فيزا / بطاقة' THEN total ELSE 0 END),0) card_sales,COALESCE(SUM(CASE WHEN payment_method NOT IN ('نقدي','فيزا / بطاقة') THEN total ELSE 0 END),0) other_sales FROM invoices WHERE restaurant_id=? AND date=?`).bind(r.id,date).first();
   const ex=await env.DB.prepare("SELECT COALESCE(SUM(amount),0) n FROM expenses WHERE restaurant_id=? AND date=? AND payment_method='نقدي'").bind(r.id,date).first(),actual=safeNum(b.actual_cash);if(actual===null)return json({error:"أدخل النقدية الفعلية"},400);
   const expected=Math.round((s.cash_sales-ex.n)*100)/100,id=uid(),closed=now();
   await env.DB.prepare(`INSERT INTO closings(id,restaurant_id,business_date,invoice_count,gross_subtotal,discounts,net_sales,tax_total,service_total,cash_sales,card_sales,other_sales,expenses_total,expected_cash,actual_cash,cash_difference,notes,closed_by,closed_at)
   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id,r.id,date,s.invoice_count,s.gross_subtotal,s.discounts,s.net_sales,s.tax_total,s.service_total,s.cash_sales,s.card_sales,s.other_sales,ex.n,expected,actual,Math.round((actual-expected)*100)/100,String(b.notes||""),user.id,closed).run();
   await audit(env,r,user,"close","day",id,date);return json({ok:true,closing:{id,date,...s,expenses_total:ex.n,expected_cash:expected,actual_cash:actual,cash_difference:Math.round((actual-expected)*100)/100,notes:String(b.notes||""),closed_at:closed}},201);
 }
 if(p==="/api/closing"&&method==="GET")return json({closings:(await env.DB.prepare("SELECT * FROM closings WHERE restaurant_id=? ORDER BY business_date DESC LIMIT 500").bind(r.id).all()).results});
 if(p==="/api/reports"&&method==="GET"){
   const from=url.searchParams.get("from")||today(),to=url.searchParams.get("to")||today();
   const sales=await env.DB.prepare(`SELECT date,COUNT(*) invoice_count,SUM(subtotal) subtotal,SUM(discount) discounts,SUM(tax_amount) tax,SUM(service_amount) service,SUM(total) total,
   SUM(CASE WHEN payment_method='نقدي' THEN total ELSE 0 END) cash,SUM(CASE WHEN payment_method='فيزا / بطاقة' THEN total ELSE 0 END) card
   FROM invoices WHERE restaurant_id=? AND date>=? AND date<=? GROUP BY date ORDER BY date DESC`).bind(r.id,from,to).all();
   const expenses=await env.DB.prepare("SELECT date,SUM(amount) total FROM expenses WHERE restaurant_id=? AND date>=? AND date<=? GROUP BY date ORDER BY date DESC").bind(r.id,from,to).all();
   return json({sales:sales.results,expenses:expenses.results,from,to});
 }
 if(p==="/api/export.csv"&&method==="GET"){
   const from=url.searchParams.get("from")||today(),to=url.searchParams.get("to")||today(),rows=(await env.DB.prepare("SELECT invoice_no,date,created_at,cashier,table_no,payment_method,subtotal,discount,tax_rate,tax_amount,service_rate,service_amount,total,status FROM invoices WHERE restaurant_id=? AND date>=? AND date<=? ORDER BY created_at").bind(r.id,from,to).all()).results;
   const lines=[["رقم الفاتورة","التاريخ","وقت الإنشاء","الكاشير","الطاولة","طريقة الدفع","قبل الخصم","الخصم","نسبة الضريبة","الضريبة","نسبة الخدمة","الخدمة","الإجمالي","الحالة"],...rows.map(x=>[x.invoice_no,x.date,x.created_at,x.cashier,x.table_no,x.payment_method,x.subtotal,x.discount,x.tax_rate,x.tax_amount,x.service_rate,x.service_amount,x.total,x.status])];
   return new Response("\ufeff"+lines.map(row=>row.map(csvCell).join(",")).join("\r\n"),{headers:{"content-type":"text/csv; charset=utf-8","content-disposition":`attachment; filename="sales-${from}-${to}.csv"`}});
 }
 if(p==="/api/audit"&&method==="GET")return json({logs:(await env.DB.prepare("SELECT action,entity_type,entity_id,details,created_at FROM audit_logs WHERE restaurant_id=? ORDER BY created_at DESC LIMIT 500").bind(r.id).all()).results});
 return json({error:"المسار غير موجود"},404);
}
export default {async fetch(req,env){try{return await route(req,env)}catch(e){console.error("Cashier Pro request failed:", {path:new URL(req.url).pathname, method:req.method, error:String(e?.stack||e)});return json({error:"حدث خطأ في الخادم",request_id:req.headers.get("cf-ray")||"unknown"},500)}}};
