const express=require('express');
const path=require('path');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const multer=require('multer');
const {Pool}=require('pg');

const app=express();
const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET||'change-this-secret';

app.use(express.json({limit:'12mb'}));
app.use(express.static(__dirname));

const pool=new Pool({
  connectionString:process.env.DATABASE_URL,
  ssl:process.env.DATABASE_URL?{rejectUnauthorized:false}:false
});

const upload=multer({
  storage:multer.memoryStorage(),
  limits:{files:3,fileSize:3*1024*1024},
  fileFilter:(r,f,cb)=>cb(null,/^image\/(jpeg|png|webp)$/.test(f.mimetype))
});

async function init(){
  await pool.query(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    phone VARCHAR(30) UNIQUE NOT NULL,
    role VARCHAR(20) NOT NULL CHECK(role IN ('client','provider')),
    password_hash TEXT NOT NULL,
    age INT,
    photos TEXT[] DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS age INT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS photos TEXT[] DEFAULT '{}'`);

  await pool.query(`CREATE TABLE IF NOT EXISTS requests(
    id SERIAL PRIMARY KEY,
    client_id INT REFERENCES users(id) ON DELETE CASCADE,
    assistance_type VARCHAR(20) NOT NULL CHECK(assistance_type IN ('SHORT TIME','SLEEP OVER')),
    transport_type VARCHAR(20) NOT NULL CHECK(transport_type IN ('PICK & DROP','DRIVE THROUGH')),
    area VARCHAR(160) NOT NULL,
    amount NUMERIC(12,2),
    details TEXT,
    lat DOUBLE PRECISION,
    lng DOUBLE PRECISION,
    status VARCHAR(20) DEFAULT 'OPEN',
    accepted_provider_id INT REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS interests(
    id SERIAL PRIMARY KEY,
    request_id INT REFERENCES requests(id) ON DELETE CASCADE,
    provider_id INT REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(request_id,provider_id)
  )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS messages(
    id SERIAL PRIMARY KEY,
    request_id INT REFERENCES requests(id) ON DELETE CASCADE,
    sender_id INT REFERENCES users(id) ON DELETE CASCADE,
    receiver_id INT REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
}

function auth(req,res,next){
  try{
    const h=req.headers.authorization||'';
    if(!h.startsWith('Bearer ')) throw 0;
    req.user=jwt.verify(h.slice(7),JWT_SECRET);
    next();
  }catch(e){
    res.status(401).json({error:'Not authenticated.'});
  }
}

function token(u){
  return jwt.sign(
    {id:u.id,role:u.role},
    JWT_SECRET,
    {expiresIn:'30d'}
  );
}

app.post('/api/auth/register',async(req,res)=>{
  try{
    const{name,phone,password,role}=req.body;

    if(!name||!phone||!password||!['client','provider'].includes(role))
      return res.status(400).json({error:'All fields are required.'});

    if(password.length<6)
      return res.status(400).json({
        error:'Password must be at least 6 characters.'
      });

    if((await pool.query(
      'SELECT id FROM users WHERE phone=$1',[phone]
    )).rowCount)
      return res.status(409).json({
        error:'An account with this phone number already exists.'
      });

    const ph=await bcrypt.hash(password,10);

    const r=await pool.query(
      `INSERT INTO users(name,phone,role,password_hash)
       VALUES($1,$2,$3,$4)
       RETURNING id,name,phone,role,age,photos,created_at`,
      [name,phone,role,ph]
    );

    res.status(201).json({
      token:token(r.rows[0]),
      user:r.rows[0]
    });

  }catch(e){
    console.error(e);
    res.status(500).json({error:'Unable to create account.'});
  }
});

app.post('/api/auth/login',async(req,res)=>{
  try{
    const{phone,password}=req.body;

    const r=await pool.query(
      'SELECT * FROM users WHERE phone=$1',[phone]
    );

    if(!r.rowCount ||
       !(await bcrypt.compare(password,r.rows[0].password_hash)))
      return res.status(401).json({
        error:'Invalid phone number or password.'
      });

    const u=r.rows[0];

    res.json({
      token:token(u),
      user:{
        id:u.id,
        name:u.name,
        phone:u.phone,
        role:u.role,
        age:u.age,
        photos:u.photos||[]
      }
    });

  }catch(e){
    res.status(500).json({error:'Unable to log in.'});
  }
});

app.get('/api/auth/me',auth,async(req,res)=>{
  const r=await pool.query(
    `SELECT id,name,phone,role,age,photos,created_at
     FROM users WHERE id=$1`,
    [req.user.id]
  );

  if(!r.rowCount)
    return res.status(401).json({error:'User not found.'});

  res.json({user:r.rows[0]});
});

app.put('/api/profile',auth,async(req,res)=>{
  const{age}=req.body;

  if(age!=null &&
     (!Number.isInteger(Number(age)) ||
      Number(age)<18 ||
      Number(age)>100))
    return res.status(400).json({
      error:'Age must be between 18 and 100.'
    });

  const r=await pool.query(
    `UPDATE users SET age=$1
     WHERE id=$2
     RETURNING id,name,phone,role,age,photos`,
    [age||null,req.user.id]
  );

  res.json({user:r.rows[0]});
});

app.post('/api/profile/photos',
  auth,
  upload.array('photos',3),
  async(req,res)=>{
    if(req.user.role!=='provider')
      return res.status(403).json({
        error:'Only providers can upload profile photos.'
      });

    const photos=(req.files||[]).map(
      f=>`data:${f.mimetype};base64,${f.buffer.toString('base64')}`
    );

    if(!photos.length)
      return res.status(400).json({
        error:'Select at least one image.'
      });

    const r=await pool.query(
      `UPDATE users SET photos=$1
       WHERE id=$2
       RETURNING id,name,phone,role,age,photos`,
      [photos,req.user.id]
    );

    res.json({user:r.rows[0]});
  }
);

app.post('/api/requests',auth,async(req,res)=>{
  if(req.user.role!=='client')
    return res.status(403).json({
      error:'Only clients can create requests.'
    });

  const{
    assistance_type,
    transport_type,
    area,
    amount,
    details,
    lat,
    lng
  }=req.body;

  if(!['SHORT TIME','SLEEP OVER'].includes(assistance_type) ||
     !['PICK & DROP','DRIVE THROUGH'].includes(transport_type) ||
     !area)
    return res.status(400).json({
      error:'Choose all request options and an area.'
    });

  const r=await pool.query(
    `INSERT INTO requests(
      client_id,
      assistance_type,
      transport_type,
      area,
      amount,
      details,
      lat,
      lng
    )
    VALUES($1,$2,$3,$4,$5,$6,$7,$8)
    RETURNING *`,
    [
      req.user.id,
      assistance_type,
      transport_type,
      area,
      amount||null,
      details||'',
      lat||null,
      lng||null
    ]
  );

  res.status(201).json({request:r.rows[0]});
});

app.get('/api/requests',auth,async(req,res)=>{
  let r;

  if(req.user.role==='client'){
    r=await pool.query(
      `SELECT r.*,
       COALESCE(
         (SELECT count(*)
          FROM interests i
          WHERE i.request_id=r.id),0
       ) AS interest_count
       FROM requests r
       WHERE r.client_id=$1
       ORDER BY r.created_at DESC`,
      [req.user.id]
    );
  }else{
    r=await pool.query(
      `SELECT r.*,
       u.name client_name,
       u.age client_age
       FROM requests r
       JOIN users u ON u.id=r.client_id
       WHERE r.status='OPEN'
       ORDER BY r.created_at DESC`
    );
  }

  res.json({requests:r.rows});
});

app.post('/api/requests/:id/interests',
  auth,
  async(req,res)=>{
    if(req.user.role!=='provider')
      return res.status(403).json({
        error:'Only providers can show interest.'
      });

    await pool.query(
      `INSERT INTO interests(request_id,provider_id)
       VALUES($1,$2)
       ON CONFLICT DO NOTHING`,
      [req.params.id,req.user.id]
    );

    res.json({message:'Interest sent.'});
  }
);

app.get('/api/requests/:id/providers',
  auth,
  async(req,res)=>{
    const r=await pool.query(
      `SELECT
       u.id,
       u.name,
       u.age,
       u.photos,
       u.phone,
       i.created_at
       FROM interests i
       JOIN users u ON u.id=i.provider_id
       JOIN requests q ON q.id=i.request_id
       WHERE i.request_id=$1
       AND q.client_id=$2
       ORDER BY i.created_at`,
      [req.params.id,req.user.id]
    );

    res.json({providers:r.rows});
  }
);

app.post('/api/requests/:id/accept',
  auth,
  async(req,res)=>{
    const r=await pool.query(
      `SELECT *
       FROM requests
       WHERE id=$1 AND client_id=$2`,
      [req.params.id,req.user.id]
    );

    if(!r.rowCount)
      return res.status(404).json({
        error:'Request not found.'
      });

    const p=await pool.query(
      `SELECT provider_id
       FROM interests
       WHERE request_id=$1
       AND provider_id=$2`,
      [req.params.id,req.body.provider_id]
    );

    if(!p.rowCount)
      return res.status(400).json({
        error:'Provider has not shown interest.'
      });

    await pool.query(
      `UPDATE requests
       SET accepted_provider_id=$1,
           status='ACCEPTED'
       WHERE id=$2`,
      [req.body.provider_id,req.params.id]
    );

    res.json({message:'Provider accepted.'});
  }
);

app.get('/api/chats',auth,async(req,res)=>{
  const r=await pool.query(
    `SELECT
     r.id request_id,
     r.assistance_type,
     r.transport_type,
     r.area,
     r.client_id,
     r.accepted_provider_id,
     c.name client_name,
     p.name provider_name
     FROM requests r
     JOIN users c ON c.id=r.client_id
     JOIN users p ON p.id=r.accepted_provider_id
     WHERE r.status='ACCEPTED'
     AND (r.client_id=$1 OR r.accepted_provider_id=$1)
     ORDER BY r.created_at DESC`,
    [req.user.id]
  );

  res.json({chats:r.rows});
});

app.get('/api/chats/:requestId/messages',
  auth,
  async(req,res)=>{
    const r=await pool.query(
      `SELECT
       m.id,
       m.sender_id,
       m.receiver_id,
       m.body,
       m.created_at,
       u.name sender_name
       FROM messages m
       JOIN users u ON u.id=m.sender_id
       JOIN requests q ON q.id=m.request_id
       WHERE m.request_id=$1
       AND (q.client_id=$2 OR q.accepted_provider_id=$2)
       ORDER BY m.created_at`,
      [req.params.requestId,req.user.id]
    );

    res.json({messages:r.rows});
  }
);

app.post('/api/chats/:requestId/messages',
  auth,
  async(req,res)=>{
    const q=await pool.query(
      `SELECT *
       FROM requests
       WHERE id=$1
       AND status='ACCEPTED'
       AND (client_id=$2 OR accepted_provider_id=$2)`,
      [req.params.requestId,req.user.id]
    );

    if(!q.rowCount)
      return res.status(403).json({
        error:'Chat unavailable.'
      });

    const x=q.rows[0];

    const receiver=
      x.client_id===req.user.id
      ? x.accepted_provider_id
      : x.client_id;

    if(!req.body.body?.trim())
      return res.status(400).json({
        error:'Message is empty.'
      });

    const r=await pool.query(
      `INSERT INTO messages(
        request_id,
        sender_id,
        receiver_id,
        body
      )
      VALUES($1,$2,$3,$4)
      RETURNING *`,
      [
        x.id,
        req.user.id,
        receiver,
        req.body.body.trim()
      ]
    );

    res.status(201).json({
      message:r.rows[0]
    });
  }
);

app.get('*',(req,res)=>
  res.sendFile(path.join(__dirname,'index.html'))
);

init()
  .then(()=>
    app.listen(
      PORT,
      '0.0.0.0',
      ()=>console.log(`COME BY running on ${PORT}`)
    )
  )
  .catch(e=>{
    console.error(e);
    process.exit(1);
  });
