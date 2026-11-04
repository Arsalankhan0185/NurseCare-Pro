import { pool } from './db.js';
export async function audit(req, action, table, id, nextValue = null) {
  await pool.query('INSERT INTO audit_logs(user_id,action,table_name,record_id,new_value_json,ip_address,device_info) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [req.user?.sub, action, table, id, nextValue ? JSON.stringify(nextValue) : null, req.ip, req.get('user-agent') || null]);
}
