import "dotenv/config";
import express from "express";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import Database from "better-sqlite3";
import helmet from "helmet";
import compression from "compression";
import rateLimit from "express-rate-limit";
import multer from "multer";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import {fileURLToPath} from "url";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const PORT=Number(process.env.PORT||3000);
const DATA=path.join(__dirname,"data");
const UP=path.join(__dirname,"uploads");
fs.mkdirSync(DATA,{recursive:true}); fs.mkdirSync(UP,{recursive:true});

const db=new Database(path.join(DATA,"vault.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), name TEXT DEFAULT 'StrategyVault', bio TEXT DEFAULT '', telegram TEXT DEFAULT '', facebook TEXT DEFAULT '', email TEXT DEFAULT '', avatar TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS strategies(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,category TEXT DEFAULT '',description TEXT DEFAULT '',content TEXT DEFAULT '',image TEXT DEFAULT '',video TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,content TEXT DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
if(!db.prepare("SELECT id FROM settings WHERE id=1").get()) db.prepare("INSERT INTO settings(id) VALUES(1)").run();

app.set("trust proxy",1);
app.use(helmet({contentSecurityPolicy:false}));
app.use(compression());
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:false,limit:"1mb"}));
app.use(session({
  store:new (SQLiteStoreFactory(session))({db:"sessions.sqlite",dir:DATA}),
  secret:process.env.SESSION_SECRET||"DEV_ONLY_CHANGE_ME",
  resave:false,saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:1000*60*60*8}
}));
const apiLimiter=rateLimit({windowMs:15*60*1000,max:200,standardHeaders:true,legacyHeaders:false});
const loginLimiter=rateLimit({windowMs:15*60*1000,max:10,message:{error:"Too many login attempts. Try again later."}});
app.use("/api",apiLimiter);

function hashPassword(p){return crypto.scryptSync(p,process.env.PASSWORD_SALT||"change-this-salt",32).toString("hex")}
function auth(req,res,next){if(req.session?.admin)return next();res.status(401).json({error:"Unauthorized"})}
function safeFileName(original){return crypto.randomBytes(18).toString("hex")+"-"+path.basename(original).replace(/[^a-zA-Z0-9._-]/g,"_")}
const storage=multer.diskStorage({destination:UP,filename:(req,file,cb)=>cb(null,safeFileName(file.originalname))});
const upload=multer({storage,limits:{fileSize:(Number(process.env.MAX_UPLOAD_MB||100))*1024*1024},
 fileFilter:(req,file,cb)=>cb(null,/^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime))$/.test(file.mimetype))});

app.use(express.static(path.join(__dirname,"public")));
app.use("/uploads",express.static(UP,{dotfiles:"deny",index:false}));

app.get("/api/public",(req,res)=>{
 const s=db.prepare("SELECT * FROM settings WHERE id=1").get();
 const strategies=db.prepare("SELECT id,title,category,description,image,video,created_at,updated_at FROM strategies ORDER BY updated_at DESC").all();
 res.json({settings:s,strategies});
});
app.post("/api/login",loginLimiter,(req,res)=>{
 const {password}=req.body;
 if(!password||!process.env.ADMIN_PASSWORD_HASH) return res.status(500).json({error:"Admin password is not configured."});
 const a=hashPassword(password);
 if(a!==process.env.ADMIN_PASSWORD_HASH) return res.status(401).json({error:"Wrong password."});
 req.session.admin=true; res.json({ok:true});
});
app.post("/api/logout",auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/admin",auth,(req,res)=>{
 res.json({
  settings:db.prepare("SELECT * FROM settings WHERE id=1").get(),
  strategies:db.prepare("SELECT * FROM strategies ORDER BY updated_at DESC").all(),
  notes:db.prepare("SELECT * FROM notes ORDER BY updated_at DESC").all()
 });
});
app.put("/api/settings",auth,(req,res)=>{
 const {name,bio,telegram,facebook,email,avatar}=req.body;
 db.prepare("UPDATE settings SET name=?,bio=?,telegram=?,facebook=?,email=?,avatar=? WHERE id=1").run(name||"",bio||"",telegram||"",facebook||"",email||"",avatar||"");
 res.json({ok:true});
});
app.post("/api/upload",auth,upload.single("file"),(req,res)=>{if(!req.file)return res.status(400).json({error:"Unsupported file."});res.json({url:"/uploads/"+req.file.filename,type:req.file.mimetype})});
app.post("/api/strategies",auth,(req,res)=>{
 const {title,category,description,content,image,video}=req.body;
 if(!title?.trim()) return res.status(400).json({error:"Title required."});
 const r=db.prepare("INSERT INTO strategies(title,category,description,content,image,video) VALUES(?,?,?,?,?,?)").run(title.trim(),category||"",description||"",content||"",image||"",video||"");
 res.json({id:r.lastInsertRowid});
});
app.put("/api/strategies/:id",auth,(req,res)=>{
 const {title,category,description,content,image,video}=req.body;
 db.prepare("UPDATE strategies SET title=?,category=?,description=?,content=?,image=?,video=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(title||"",category||"",description||"",content||"",image||"",video||"",req.params.id);
 res.json({ok:true});
});
app.delete("/api/strategies/:id",auth,(req,res)=>{db.prepare("DELETE FROM strategies WHERE id=?").run(req.params.id);res.json({ok:true})});
app.post("/api/notes",auth,(req,res)=>{
 const {title,content}=req.body;if(!title?.trim())return res.status(400).json({error:"Title required."});
 const r=db.prepare("INSERT INTO notes(title,content) VALUES(?,?)").run(title.trim(),content||"");res.json({id:r.lastInsertRowid});
});
app.put("/api/notes/:id",auth,(req,res)=>{db.prepare("UPDATE notes SET title=?,content=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(req.body.title||"",req.body.content||"",req.params.id);res.json({ok:true})});
app.delete("/api/notes/:id",auth,(req,res)=>{db.prepare("DELETE FROM notes WHERE id=?").run(req.params.id);res.json({ok:true})});

app.use((err,req,res,next)=>{console.error(err);res.status(400).json({error:"Request failed."})});
app.listen(PORT,()=>console.log(`StrategyVault running on http://localhost:${PORT}`));
