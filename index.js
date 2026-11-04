import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import argon2 from 'argon2';
import { z } from 'zod';
import { pool } from './db.js';
import { auth, allow, signToken, encrypt, decrypt } from './security.js';
import { audit } from './audit.js';

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || true }));
app.use(express.json({ limit: '1mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15*60*1000, limit: 30 }));
const wrap = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next);
const idSchema = z.string().uuid();

app.get('/api/health', (req,res) => res.json({status:'ok', service:'NurseCare Pro API'}));
app.post('/api/auth/register', wrap(async (req,res) => {
  const data = z.object({username:z.string().min(3).max(60),password:z.string().min(12).max(200),fullName:z.string().min(2),role:z.enum(['nurse_admin','charge_nurse','staff_nurse']).default('staff_nurse')}).parse(req.body);
  const role = await pool.query('SELECT id,name FROM roles WHERE name=$1',[data.role]);
  const hash = await argon2.hash(data.password, {type:argon2.argon2id});
  const user = await pool.query('INSERT INTO users(username,password_hash,role_id) VALUES($1,$2,$3) RETURNING id,username',[data.username,hash,role.rows[0].id]);
  await pool.query('INSERT INTO nurses(user_id,full_name) VALUES($1,$2)',[user.rows[0].id,data.fullName]);
  res.status(201).json({user:user.rows[0], token:signToken({...user.rows[0],role:data.role})});
}));
app.post('/api/auth/login', wrap(async (req,res) => {
  const d=z.object({username:z.string(),password:z.string()}).parse(req.body);
  const r=await pool.query('SELECT u.id,u.username,u.password_hash,ro.name role FROM users u JOIN roles ro ON ro.id=u.role_id WHERE u.username=$1 AND u.is_active=true',[d.username]);
  if(!r.rowCount || !(await argon2.verify(r.rows[0].password_hash,d.password))) return res.status(401).json({error:'Invalid credentials'});
  await pool.query('UPDATE users SET last_login_at=now(),failed_attempts=0 WHERE id=$1',[r.rows[0].id]);
  res.json({token:signToken(r.rows[0]),user:{id:r.rows[0].id,username:r.rows[0].username,role:r.rows[0].role}});
}));
app.use('/api',auth);

app.get('/api/dashboard',wrap(async(req,res)=>{
 const [p,t,s,d,m]=await Promise.all([
  pool.query("SELECT count(*)::int count FROM admissions WHERE status='admitted'"),
  pool.query("SELECT count(*)::int count FROM nursing_tasks WHERE status='pending'"),
  pool.query("SELECT count(*)::int count FROM sbar_reports WHERE status IN ('draft','sent')"),
  pool.query("SELECT count(*)::int count FROM discharge_plans WHERE status NOT IN ('discharged','cancelled')"),
  pool.query("SELECT count(*)::int count FROM medication_schedules ms JOIN medication_orders mo ON mo.id=ms.order_id WHERE mo.status='active' AND ms.scheduled_datetime >= now() AND ms.scheduled_datetime < now()+interval '24 hours'")
 ]);
 res.json({patients:p.rows[0].count,pendingTasks:t.rows[0].count,pendingSbar:s.rows[0].count,activeDischarges:d.rows[0].count,medicationsToday:m.rows[0].count});
}));
app.get('/api/patients',wrap(async(req,res)=>{
 const r=await pool.query("SELECT p.id,p.patient_no,p.full_name,p.date_of_birth,p.gender,p.blood_group,a.diagnosis,a.status admission_status FROM patients p LEFT JOIN LATERAL (SELECT diagnosis,status FROM admissions WHERE patient_id=p.id ORDER BY admission_datetime DESC LIMIT 1) a ON true WHERE p.is_active=true ORDER BY p.created_at DESC LIMIT 250");
 res.json(r.rows);
}));
app.post('/api/patients',allow('nurse_admin','charge_nurse','staff_nurse'),wrap(async(req,res)=>{
 const d=z.object({patientNo:z.string().min(1),fullName:z.string().min(2),dateOfBirth:z.string().optional(),gender:z.string().optional(),bloodGroup:z.string().optional(),contact:z.string().optional(),address:z.string().optional(),emergencyContact:z.string().optional(),diagnosis:z.string().optional()}).parse(req.body);
 const c=await pool.connect(); try { await c.query('BEGIN');
 const p=await c.query('INSERT INTO patients(patient_no,full_name,date_of_birth,gender,blood_group,contact_encrypted,address_encrypted,emergency_contact_encrypted,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id,patient_no,full_name',[d.patientNo,d.fullName,d.dateOfBirth||null,d.gender||null,d.bloodGroup||null,encrypt(d.contact),encrypt(d.address),encrypt(d.emergencyContact),req.user.sub]);
 if(d.diagnosis) await c.query("INSERT INTO admissions(patient_id,diagnosis) VALUES($1,$2)",[p.rows[0].id,d.diagnosis]);
 await c.query('COMMIT'); await audit(req,'create','patients',p.rows[0].id,{patient_no:d.patientNo}); res.status(201).json(p.rows[0]);
 } catch(e){await c.query('ROLLBACK');throw e;} finally{c.release();}
}));
app.get('/api/sbar',wrap(async(req,res)=>{const r=await pool.query('SELECT s.*,p.patient_no,p.full_name FROM sbar_reports s JOIN admissions a ON a.id=s.admission_id JOIN patients p ON p.id=a.patient_id ORDER BY s.created_at DESC LIMIT 100');res.json(r.rows);}));
app.post('/api/sbar',wrap(async(req,res)=>{
 const d=z.object({admissionId:idSchema,situation:z.string().min(1),background:z.string().default(''),assessment:z.string().default(''),recommendation:z.string().default(''),status:z.enum(['draft','sent']).default('draft')}).parse(req.body);
 const nurse=await pool.query('SELECT id FROM nurses WHERE user_id=$1',[req.user.sub]); if(!nurse.rowCount)return res.status(400).json({error:'Nurse profile missing'});
 const r=await pool.query('INSERT INTO sbar_reports(admission_id,author_nurse_id,status,situation,background,assessment,recommendation,sent_at) VALUES($1,$2,$3,$4,$5,$6,$7,CASE WHEN $3=''sent'' THEN now() END) RETURNING *',[d.admissionId,nurse.rows[0].id,d.status,d.situation,d.background,d.assessment,d.recommendation]);
 await audit(req,'create','sbar_reports',r.rows[0].id,{status:d.status});res.status(201).json(r.rows[0]);
}));
app.post('/api/sbar/:id/acknowledge',wrap(async(req,res)=>{
 const r=await pool.query("UPDATE sbar_reports SET status='acknowledged' WHERE id=$1 AND status='sent' RETURNING id",[req.params.id]);
 if(!r.rowCount)return res.status(404).json({error:'Sent handover not found'});
 await audit(req,'acknowledge','sbar_reports',r.rows[0].id);res.json({ok:true});
}));
app.get('/api/tasks',wrap(async(req,res)=>{const r=await pool.query('SELECT * FROM nursing_tasks ORDER BY due_datetime NULLS LAST LIMIT 200');res.json(r.rows);}));
app.post('/api/tasks',wrap(async(req,res)=>{
 const d=z.object({admissionId:idSchema,title:z.string().min(2),category:z.enum(['hygiene','mobility','wound_care','monitoring','other']).default('other'),priority:z.enum(['low','normal','high','urgent']).default('normal'),dueDatetime:z.string().optional()}).parse(req.body);
 const r=await pool.query('INSERT INTO nursing_tasks(admission_id,title,category,priority,due_datetime) VALUES($1,$2,$3,$4,$5) RETURNING *',[d.admissionId,d.title,d.category,d.priority,d.dueDatetime||null]);await audit(req,'create','nursing_tasks',r.rows[0].id);res.status(201).json(r.rows[0]);
}));
app.patch('/api/tasks/:id',wrap(async(req,res)=>{
 const d=z.object({status:z.enum(['pending','in_progress','completed','cancelled'])}).parse(req.body);
 const r=await pool.query('UPDATE nursing_tasks SET status=$1,completed_at=CASE WHEN $1=''completed'' THEN now() ELSE completed_at END,updated_at=now() WHERE id=$2 RETURNING *',[d.status,req.params.id]);
 if(!r.rowCount)return res.status(404).json({error:'Task not found'});await audit(req,'update','nursing_tasks',req.params.id,{status:d.status});res.json(r.rows[0]);
}));
app.post('/api/vitals',wrap(async(req,res)=>{
 const d=z.object({admissionId:idSchema,systolicBp:z.number().optional(),diastolicBp:z.number().optional(),heartRate:z.number().optional(),respiratoryRate:z.number().optional(),temperature:z.number().optional(),spo2:z.number().optional(),painScore:z.number().min(0).max(10).optional(),bloodGlucose:z.number().optional()}).parse(req.body);
 const nurse=await pool.query('SELECT id FROM nurses WHERE user_id=$1',[req.user.sub]);
 const r=await pool.query('INSERT INTO vital_signs(admission_id,recorded_by,systolic_bp,diastolic_bp,heart_rate,respiratory_rate,temperature,spo2,pain_score,blood_glucose) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',[d.admissionId,nurse.rows[0]?.id,d.systolicBp,d.diastolicBp,d.heartRate,d.respiratoryRate,d.temperature,d.spo2,d.painScore,d.bloodGlucose]);await audit(req,'create','vital_signs',r.rows[0].id);res.status(201).json(r.rows[0]);
}));
app.post('/api/medications/:scheduleId/administrations',wrap(async(req,res)=>{
 const d=z.object({status:z.enum(['given','not_given','delayed','refused']),allergyCheckDone:z.literal(true),orderCheckDone:z.literal(true),omissionReason:z.string().optional(),delayReason:z.string().optional()}).parse(req.body);
 const nurse=await pool.query('SELECT id FROM nurses WHERE user_id=$1',[req.user.sub]);
 const valid=await pool.query("SELECT ms.id FROM medication_schedules ms JOIN medication_orders mo ON mo.id=ms.order_id WHERE ms.id=$1 AND mo.status='active'",[req.params.scheduleId]);
 if(!valid.rowCount)return res.status(404).json({error:'No active authorized medication order for this schedule'});
 const r=await pool.query('INSERT INTO medication_administrations(schedule_id,status,administered_by,allergy_check_done,order_check_done,omission_reason,delay_reason) VALUES($1,$2,$3,true,true,$4,$5) RETURNING *',[req.params.scheduleId,d.status,nurse.rows[0]?.id,d.omissionReason||null,d.delayReason||null]);await audit(req,'create','medication_administrations',r.rows[0].id,{status:d.status});res.status(201).json(r.rows[0]);
}));
app.post('/api/discharges',wrap(async(req,res)=>{
 const d=z.object({admissionId:idSchema,plannedDate:z.string().optional(),destination:z.string().optional()}).parse(req.body);
 const r=await pool.query("INSERT INTO discharge_plans(admission_id,planned_discharge_date,destination,status) VALUES($1,$2,$3,'planned') RETURNING *",[d.admissionId,d.plannedDate||null,d.destination||null]);await audit(req,'create','discharge_plans',r.rows[0].id);res.status(201).json(r.rows[0]);
}));
app.get('/api/discharges',wrap(async(req,res)=>{const r=await pool.query('SELECT dp.*,p.patient_no,p.full_name FROM discharge_plans dp JOIN admissions a ON a.id=dp.admission_id JOIN patients p ON p.id=a.patient_id ORDER BY dp.created_at DESC');res.json(r.rows);}));
app.post('/api/discharges/:id/checklist',wrap(async(req,res)=>{
 const d=z.object({itemLabel:z.string().min(2),isMandatory:z.boolean().default(true),isDone:z.boolean(),note:z.string().optional()}).parse(req.body);
 const r=await pool.query('INSERT INTO discharge_checklist_items(plan_id,item_label,is_mandatory,is_done,note,done_at) VALUES($1,$2,$3,$4,$5,CASE WHEN $4 THEN now() END) RETURNING *',[req.params.id,d.itemLabel,d.isMandatory,d.isDone,d.note||null]);await audit(req,'create','discharge_checklist_items',r.rows[0].id);res.status(201).json(r.rows[0]);
}));
app.post('/api/discharges/:id/approval',allow('nurse_admin','charge_nurse'),wrap(async(req,res)=>{
 const d=z.object({clinicianId:idSchema,approvalNote:z.string().optional()}).parse(req.body);
 await pool.query('INSERT INTO discharge_approvals(plan_id,clinician_id,approved_at,approval_note) VALUES($1,$2,now(),$3)',[req.params.id,d.clinicianId,d.approvalNote||null]);
 await pool.query("UPDATE discharge_plans SET status='approved',updated_at=now() WHERE id=$1",[req.params.id]);await audit(req,'approve','discharge_plans',req.params.id);res.json({ok:true});
}));
app.post('/api/discharges/:id/finalize',allow('nurse_admin','charge_nurse'),wrap(async(req,res)=>{
 const c=await pool.connect();try{await c.query('BEGIN');
 const p=await c.query('SELECT * FROM discharge_plans WHERE id=$1 FOR UPDATE',[req.params.id]);if(!p.rowCount)throw Object.assign(new Error('Discharge plan not found'),{status:404});
 const [check,disc,approval]=await Promise.all([
  c.query('SELECT count(*)::int n FROM discharge_checklist_items WHERE plan_id=$1 AND is_mandatory=true AND is_done=false',[req.params.id]),
  c.query("SELECT count(*)::int n FROM discharge_medication_reconciliation WHERE plan_id=$1 AND reconciliation_status='discrepancy' AND reviewed_at IS NULL",[req.params.id]),
  c.query('SELECT count(*)::int n FROM discharge_approvals WHERE plan_id=$1',[req.params.id])
 ]);
 if(check.rows[0].n||disc.rows[0].n||!approval.rows[0].n)throw Object.assign(new Error('Cannot finalize: mandatory checklist incomplete, medication discrepancy open, or clinician approval missing'),{status:409});
 const done=await c.query("UPDATE discharge_plans SET status='discharged',discharge_datetime=now(),finalized_at=now(),finalized_by=$2 WHERE id=$1 RETURNING *",[req.params.id,req.user.sub]);
 await c.query("UPDATE admissions SET status='discharged' WHERE id=$1",( [p.rows[0].admission_id] ));await c.query('COMMIT');await audit(req,'finalize','discharge_plans',req.params.id);res.json(done.rows[0]);
 }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
}));
app.use((err,req,res,next)=>{console.error(err);res.status(err.status|| (err.name==='ZodError'?400:500)).json({error:err.name==='ZodError'?'Invalid request data':err.message||'Server error'});});
const port=process.env.PORT||3000;app.listen(port,()=>console.log(`NurseCare Pro API listening on ${port}`));
