// DogMarket - Backend Scaffold (Node + Express)
// Files included in this single code document for convenience:
// 1) package.json
// 2) server.js
// 3) db.json (initial data file used by lowdb)
// Save package.json and server.js as separate files and run `npm install` then `node server.js`.

/* ----------------------- package.json ----------------------- */
// Save this block as package.json
{
  "name": "dogmarket-backend",
  "version": "1.0.0",
  "description": "Simple Express backend scaffold for DogMarket prototype",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "express-validator": "^7.0.1",
    "helmet": "^7.0.0",
    "jsonwebtoken": "^9.0.0",
    "lowdb": "^6.0.1",
    "multer": "^1.4.5-lts.1",
    "nanoid": "^4.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}

/* ----------------------- db.json ----------------------- */
// Save this block as db.json (initial content for lowdb)
{
  "users": [],
  "products": [
    {"id": "p1","title":"Labrador Retriever - 4 months","price":120000,"category":"Puppy","image":"/uploads/lab.jpg","vendorId":"v101"},
    {"id": "p2","title":"Premium Dog Leash (leather)","price":5500,"category":"Accessory","image":"/uploads/leash.jpg","vendorId":"v102"}
  ],
  "vendors": [
    {"id":"v101","name":"Happy Paws Kennel","location":"Lagos","rating":4.8},
    {"id":"v102","name":"Urban Pet Supplies","location":"Abuja","rating":4.5}
  ],
  "vets": [
    {"id":"vet201","name":"Dr. Amina Bello","clinic":"Lagos Vet Clinic","lat":6.5244,"lng":3.3792,"license":"VET-001","specialty":"Surgery"}
  ],
  "orders": []
}

/* ----------------------- server.js ----------------------- */
// Save this block as server.js

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const multer = require('multer');
const { nanoid } = require('nanoid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { Low, JSONFile } = require('lowdb');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_prod';

// lowdb setup (file-based JSON DB)
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter);

async function initDB(){
  await db.read();
  db.data = db.data || { users: [], products: [], vendors: [], vets: [], orders: [] };
  await db.write();
}
initDB();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// multer setup for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g,'_'))
});
const upload = multer({ storage });

// --- Helpers ---
function generateId(prefix='id'){ return prefix + nanoid(8); }
function authMiddleware(req,res,next){
  const auth = req.headers.authorization; if(!auth) return res.status(401).json({message:'Missing Authorization header'});
  const token = auth.replace('Bearer ','');
  try{ const payload = jwt.verify(token, JWT_SECRET); req.user = payload; next(); } catch(e){ return res.status(401).json({message:'Invalid token'}) }
}

// --- Auth ---
app.post('/api/auth/register', [
  body('name').isString(), body('email').isEmail(), body('password').isLength({min:6}), body('role').isIn(['buyer','vendor','vet'])
], async (req,res)=>{
  await db.read();
  const errors = validationResult(req); if(!errors.isEmpty()) return res.status(400).json({errors: errors.array()});
  const {name,email,password,role} = req.body;
  const existing = db.data.users.find(u=>u.email===email); if(existing) return res.status(400).json({message:'Email exists'});
  const hash = await bcrypt.hash(password,10); const id = generateId('u');
  const user = {id,name,email,password:hash,role,createdAt:Date.now()};
  db.data.users.push(user); await db.write();
  const token = jwt.sign({id,name,email,role}, JWT_SECRET, {expiresIn:'7d'});
  res.json({token,user:{id,name,email,role}});
});

app.post('/api/auth/login', [ body('email').isEmail(), body('password').isString() ], async (req,res)=>{
  await db.read(); const {email,password} = req.body;
  const u = db.data.users.find(x=>x.email===email); if(!u) return res.status(400).json({message:'Invalid credentials'});
  const ok = await bcrypt.compare(password,u.password); if(!ok) return res.status(400).json({message:'Invalid credentials'});
  const token = jwt.sign({id:u.id,name:u.name,email:u.email,role:u.role}, JWT_SECRET, {expiresIn:'7d'});
  res.json({token,user:{id:u.id,name:u.name,email:u.email,role:u.role}});
});

// --- Products ---
app.get('/api/products', async (req,res)=>{
  await db.read(); const q = (req.query.q||'').toLowerCase();
  let products = db.data.products || [];
  if(q) products = products.filter(p=>p.title.toLowerCase().includes(q) || p.category.toLowerCase().includes(q));
  res.json(products);
});

app.post('/api/products', authMiddleware, upload.single('image'), async (req,res)=>{
  // Only vendors can create products
  if(req.user.role !== 'vendor') return res.status(403).json({message:'Only vendors can create products'});
  await db.read();
  const {title,price,category} = req.body; if(!title||!price) return res.status(400).json({message:'Missing title or price'});
  const image = req.file ? '/uploads/' + path.basename(req.file.path) : req.body.image || '';
  const id = generateId('p');
  const p = {id,title,price:parseFloat(price),category,image,vendorId:req.user.id,createdAt:Date.now()};
  db.data.products.unshift(p); await db.write(); res.json(p);
});

// --- Vendors ---
app.get('/api/vendors', async (req,res)=>{ await db.read(); res.json(db.data.vendors || []); });
app.post('/api/vendors', authMiddleware, async (req,res)=>{
  if(req.user.role !== 'vendor') return res.status(403).json({message:'Only vendors can register vendor profile'});
  await db.read(); const {name,location} = req.body; if(!name) return res.status(400).json({message:'Missing name'});
  const existing = (db.data.vendors||[]).find(v=>v.id===req.user.id);
  const vendor = existing || {id:req.user.id, name, location, rating:0};
  if(!existing) db.data.vendors.push(vendor);
  await db.write(); res.json(vendor);
});

// --- Vets ---
app.get('/api/vets', async (req,res)=>{
  // optional: ?lat=&lng=&radius_km=
  await db.read(); let vets = db.data.vets || [];
  const {lat,lng,radius_km} = req.query;
  if(lat && lng){
    const R=6371; const toRad = d=>d*Math.PI/180;
    const lat1 = parseFloat(lat), lon1 = parseFloat(lng);
    vets = vets.map(v=>{ const dLat = toRad(v.lat-lat1); const dLon = toRad(v.lng-lon1); const a = Math.sin(dLat/2)**2 + Math.cos(toRad(lat1))*Math.cos(toRad(v.lat))*Math.sin(dLon/2)**2; const c = 2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a)); const dist = R*c; return {...v,dist}; });
    if(radius_km) vets = vets.filter(v=>v.dist <= parseFloat(radius_km));
    vets.sort((a,b)=>a.dist-b.dist);
  }
  res.json(vets);
});

app.post('/api/vets', authMiddleware, async (req,res)=>{
  if(req.user.role !== 'vet') return res.status(403).json({message:'Only users with role vet can register vet profile'});
  await db.read(); const {name,clinic,license,lat,lng,specialty} = req.body; if(!name||!clinic||!license) return res.status(400).json({message:'Missing required fields'});
  const v = {id:req.user.id, name, clinic, license, lat:parseFloat(lat)||null, lng:parseFloat(lng)||null, specialty: specialty || 'General'};
  // replace or add
  db.data.vets = (db.data.vets||[]).filter(x=>x.id !== req.user.id);
  db.data.vets.push(v); await db.write(); res.json(v);
});

// --- Orders ---
app.post('/api/orders', authMiddleware, async (req,res)=>{
  await db.read(); const {items,shipping} = req.body; if(!items || !Array.isArray(items)) return res.status(400).json({message:'Items required'});
  const id = generateId('o'); const total = items.reduce((s,it)=>{ const p = db.data.products.find(x=>x.id===it.productId); return s + (p ? p.price * (it.qty||1) : 0); },0);
  const order = {id, userId:req.user.id, items, shipping, total, status:'pending', createdAt:Date.now()};
  db.data.orders.push(order); await db.write(); res.json(order);
});

app.get('/api/orders', authMiddleware, async (req,res)=>{ await db.read(); const userId = req.user.id; const role = req.user.role; let orders = db.data.orders || [];
  if(role === 'vendor'){
    // vendor: return orders containing vendor's products
    const vendorProducts = (db.data.products||[]).filter(p=>p.vendorId===req.user.id).map(p=>p.id);
    orders = orders.filter(o => o.items.some(it=>vendorProducts.includes(it.productId)));
  } else {
    orders = orders.filter(o=>o.userId===userId);
  }
  res.json(orders);
});

// --- Health check ---
app.get('/api/health', (req,res)=> res.json({status:'ok', uptime: process.uptime()}));

app.listen(PORT, ()=> console.log(`DogMarket API running on http://localhost:${PORT}`));

/* ----------------------- Notes for developers -----------------------
 * - This scaffold uses lowdb for quick file-based persistence (good for prototypes).
 * - Replace lowdb with PostgreSQL, MySQL, or MongoDB for production.
 * - Use environment variables for secrets (JWT_SECRET) and configure HTTPS in production.
 * - Add input sanitization, rate limiting, request logging, and RBAC as needed.
 * - Implement vet license verification and KYC processes for vendors.
 * - Integrate payment providers (Paystack, Flutterwave, Stripe). Create secure order/payment webhooks.
 * - Add tests and CI/CD.

 How to run:
 1) Save package.json, server.js, and db.json as separate files in a folder.
 2) mkdir uploads
 3) npm install
 4) npm run start

 Integration with the frontend prototype:
 - Update frontend fetch URLs to point to http://localhost:4000/api/... (or configured host/port).
 - For protected endpoints (create product, register vet), call /api/auth/login to get token and set Authorization: Bearer <token> header.
------------------------------------------------------------------------ */
