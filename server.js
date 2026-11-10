const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();

app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*', methods: ["GET", "POST", "PUT", "DELETE"], credentials: true }
});

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

const pool = mysql.createPool(process.env.TIDB_URI);

const getBrevoTransport = () => {
    const host = process.env.BREVO_SMTP_HOST || 'smtp-relay.brevo.com';
    const port = Number(process.env.BREVO_SMTP_PORT || 587);
    const user = process.env.BREVO_SMTP_USER;
    const pass = process.env.BREVO_SMTP_KEY;
    if (!user || !pass) throw new Error('Brevo SMTP credentials are not configured.');
    return nodemailer.createTransport({ host, port, secure: port === 465, auth: { user, pass } });
};

const sendPasswordResetEmail = async (email, resetUrl) => {
    const transporter = getBrevoTransport();
    const fromEmail = process.env.BREVO_SENDER_EMAIL;
    if (!fromEmail) throw new Error('BREVO_SENDER_EMAIL is not configured.');
    const fromName = process.env.BREVO_SENDER_NAME || '3K Kitchen';
    await transporter.sendMail({
        from: { name: fromName, address: fromEmail },
        to: email,
        subject: 'Reset your 3K Kitchen password',
        text: `We received a request to reset your 3K Kitchen password. Open this link within 30 minutes to choose a new password: ${resetUrl}\n\nIf you did not request this, you can ignore this email.`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>Reset your password</h1><p>We received a request to reset your 3K Kitchen password.</p><p><a href="${resetUrl}" style="display:inline-block;padding:12px 20px;background:#815633;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold">Choose a new password</a></p><p>This link expires in 30 minutes. If you did not request this, you can ignore this email.</p></div>`
    });
};

const sendRecoveryDeniedEmail = async (email, note = '') => {
    const transporter = getBrevoTransport();
    const fromEmail = process.env.BREVO_SENDER_EMAIL;
    if (!fromEmail) throw new Error('BREVO_SENDER_EMAIL is not configured.');
    const fromName = process.env.BREVO_SENDER_NAME || '3K Kitchen';
    const decisionText = `Your 3K Kitchen account recovery request was denied.${note ? ` Admin note: ${note}` : ''}`;
    await transporter.sendMail({
        from: { name: fromName, address: fromEmail },
        to: email,
        subject: '3K Kitchen account recovery update',
        text: `${decisionText}\n\nIf you did not submit this request, contact 3K Kitchen support.`
    });
};

const sendRecoveryApprovedEmail = async (email, resetUrl) => {
    const transporter = getBrevoTransport();
    const fromEmail = process.env.BREVO_SENDER_EMAIL;
    if (!fromEmail) throw new Error('BREVO_SENDER_EMAIL is not configured.');
    await transporter.sendMail({
        from: { name: process.env.BREVO_SENDER_NAME || '3K Kitchen', address: fromEmail },
        to: email,
        subject: '3K Kitchen account recovery approved',
        text: `Your account recovery was approved. Use this link within 30 minutes to set a new password: ${resetUrl}\n\nIf you did not submit this request, contact 3K Kitchen support.`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>Recovery approved</h1><p>Your 3K Kitchen account recovery request was approved.</p><p><a href="${resetUrl}" style="display:inline-block;padding:12px 20px;background:#815633;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold">Reset your password</a></p><p>This link expires in 30 minutes. If you did not submit this request, contact 3K Kitchen support.</p></div>`
    });
};

const initializeDB = async () => {
    const columnsToAdd = [
        'ALTER TABLE users ADD COLUMN phone VARCHAR(50) DEFAULT NULL',
        'ALTER TABLE users ADD COLUMN dob DATE DEFAULT NULL',
        'ALTER TABLE users ADD COLUMN last_updated DATETIME DEFAULT NULL',
        'ALTER TABLE users ADD COLUMN branch VARCHAR(255) DEFAULT NULL',
        'ALTER TABLE users ADD COLUMN password_reset_token_hash CHAR(64) DEFAULT NULL',
        'ALTER TABLE users ADD COLUMN password_reset_expires_at DATETIME DEFAULT NULL',
        'ALTER TABLE orders ADD COLUMN chat_expires_at DATETIME DEFAULT NULL',
        'ALTER TABLE orders ADD COLUMN customer_name VARCHAR(255) DEFAULT NULL',
        'ALTER TABLE orders ADD COLUMN gcash_reference VARCHAR(13) DEFAULT NULL',
        'ALTER TABLE orders ADD COLUMN cash_tendered DECIMAL(10,2) DEFAULT NULL',
        'ALTER TABLE orders ADD COLUMN change_given DECIMAL(10,2) DEFAULT NULL'
    ];

    for (let query of columnsToAdd) {
        try {
            await pool.execute(query);
        } catch (e) {
            // Ignore error if this specific column already exists
        }
    }

    for (const column of ['payment_method', 'order_type']) {
        try {
            const [columns] = await pool.execute(`SHOW COLUMNS FROM orders LIKE '${column}'`);
            if (columns[0]?.Type?.toLowerCase().startsWith('enum(')) {
                await pool.execute(`ALTER TABLE orders MODIFY ${column} VARCHAR(50) NOT NULL`);
            }
        } catch (e) {
            console.error(`Failed to prepare orders.${column} for supported order values`, e);
        }
    }

    try {
        await pool.execute(`CREATE TABLE IF NOT EXISTS activity_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_name VARCHAR(255) NOT NULL,
            role VARCHAR(50) NOT NULL,
            action VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
    } catch (e) { console.error('Failed to create activity_logs table', e); }

    try {
        await pool.execute(`CREATE TABLE IF NOT EXISTS account_recovery_requests (
            id INT AUTO_INCREMENT PRIMARY KEY,
            account_email VARCHAR(255) NOT NULL,
            account_name VARCHAR(255) NOT NULL,
            registered_phone VARCHAR(50) NOT NULL,
            registered_dob DATE DEFAULT NULL,
            new_email VARCHAR(255) NOT NULL,
            account_details TEXT,
            status VARCHAR(20) NOT NULL DEFAULT 'Pending',
            review_note VARCHAR(1000) DEFAULT NULL,
            reviewed_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_at DATETIME DEFAULT NULL,
            INDEX idx_recovery_status_created (status, created_at),
            INDEX idx_recovery_email (account_email)
        )`);
    } catch (e) { console.error('Failed to create account_recovery_requests table', e); }
};
const databaseReady = initializeDB();

// Helper to log activities
const logActivity = async (userId, action) => {
    try {
        const [rows] = await pool.execute('SELECT firstname, lastname, role FROM users WHERE id = ?', [userId]);
        if (rows.length > 0) {
            const name = `${rows[0].firstname} ${rows[0].lastname}`;
            await pool.execute('INSERT INTO activity_logs (user_name, role, action) VALUES (?, ?, ?)', [name, rows[0].role, action]);
        }
    } catch(err) { console.error('Activity Log Error:', err); }
};

io.on('connection', (socket) => {
    socket.on('join_order', (orderId) => { socket.join(`order_${orderId}`); });
    socket.on('send_message', async (data) => {
        try {
            const [orders] = await pool.execute(
                `SELECT status, chat_expires_at > CURRENT_TIMESTAMP AS chat_time_remaining
                 FROM orders WHERE id = ?`,
                [data.orderId]
            );
            const order = orders[0];
            if (!order || order.status === 'Cancelled' || (order.status === 'Completed' && !order.chat_time_remaining)) {
                io.to(`order_${data.orderId}`).emit('chat_closed', { orderId: data.orderId });
                return;
            }
            await pool.execute('INSERT INTO order_chats (order_id, sender, message) VALUES (?, ?, ?)', [data.orderId, data.sender, data.text]);
            io.to(`order_${data.orderId}`).emit('receive_message', data);
        } catch (error) { console.error('Socket DB Insert Error:', error); }
    });
    socket.on('status_change', (data) => {
        io.to(`order_${data.orderId}`).emit('status_updated', data);
        io.emit('dashboard_refresh'); 
    });
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

const verifyAdminOrStaff = (req, res, next) => {
    if (req.user && (req.user.role === 'admin' || req.user.role === 'cashier' || req.user.role === 'rider')) next();
    else res.status(403).json({ error: 'Staff access required' });
};

const verifyAdminOnly = (req, res, next) => {
    if (req.user?.role === 'admin') next();
    else res.status(403).json({ error: 'Administrator access required' });
};

const verifyCurrentAdminPassword = async (userId, password) => {
    if (typeof password !== 'string' || !password) return false;
    const [admins] = await pool.execute('SELECT password, role FROM users WHERE id = ?', [userId]);
    return admins[0]?.role === 'admin' && bcrypt.compare(password, admins[0].password);
};

app.get('/', (req, res) => res.send('3K Kitchen API is running successfully!'));

app.get('/api/admin/activity-logs', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [logs] = await pool.execute('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 500');
        res.json(logs);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch logs' }); }
});

app.get('/api/admin/users', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [users] = await pool.execute('SELECT id, firstname, lastname, email, role, branch, created_at FROM users WHERE role IN ("admin", "cashier") ORDER BY role, firstname');
        res.json(users);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch users' }); }
});

// NEW ENDPOINT: Fetch Customers for the Admin Panel
app.get('/api/admin/customers', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [customers] = await pool.execute('SELECT id, firstname, lastname, email, phone, dob, created_at FROM users WHERE role = "customer" ORDER BY created_at DESC');
        res.json(customers);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch customers' }); }
});

app.post('/api/admin/users', authenticateToken, verifyAdminOnly, async (req, res) => {
    const { firstname, lastname, email, password, role, branch, adminPassword } = req.body;
    try {
        if (!['admin', 'cashier'].includes(role)) {
            return res.status(400).json({ error: 'New accounts must be an admin or cashier.' });
        }
        if (!await verifyCurrentAdminPassword(req.user.id, adminPassword)) {
            return res.status(403).json({ error: 'The admin password is incorrect.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (firstname, lastname, email, password, role, phone, dob, branch) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)',
            [firstname, lastname, email, hashedPassword, role, branch || null]
        );
        await logActivity(req.user.id, `Created new ${role} account: ${email}`);
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) { 
        res.status(500).json({ error: 'Failed to create user. Email may already exist.' }); 
    }
});

app.put('/api/admin/users/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { firstname, lastname, email, password, role, branch, adminPassword } = req.body;
    try {
        if (!['admin', 'cashier', 'rider'].includes(role)) {
            return res.status(400).json({ error: 'Invalid staff role.' });
        }
        const [targetUsers] = await pool.execute('SELECT role FROM users WHERE id = ?', [req.params.id]);
        if (!targetUsers.length) return res.status(404).json({ error: 'Account not found.' });
        if ((role === 'admin' || targetUsers[0].role === 'admin') && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Only an administrator can manage admin accounts.' });
        }
        if (role === 'admin' && !await verifyCurrentAdminPassword(req.user.id, adminPassword)) {
            return res.status(403).json({ error: 'The admin password is incorrect.' });
        }
        if (password && password.trim() !== '') {
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.execute(
                'UPDATE users SET firstname=?, lastname=?, email=?, password=?, role=?, branch=? WHERE id=?',
                [firstname, lastname, email, hashedPassword, role, branch || null, req.params.id]
            );
        } else {
            await pool.execute(
                'UPDATE users SET firstname=?, lastname=?, email=?, role=?, branch=? WHERE id=?',
                [firstname, lastname, email, role, branch || null, req.params.id]
            );
        }
        await logActivity(req.user.id, `Updated account details for ID: ${req.params.id}`);
        res.json({ message: 'User updated successfully' });
    } catch (error) { res.status(500).json({ error: 'Failed to update user.' }); }
});

app.delete('/api/admin/users/:id', authenticateToken, verifyAdminOnly, async (req, res) => {
    try {
        const [targetUsers] = await pool.execute('SELECT id, role FROM users WHERE id = ?', [req.params.id]);
        if (!targetUsers.length) return res.status(404).json({ error: 'Account not found.' });
        if (Number(req.params.id) === Number(req.user.id)) {
            return res.status(400).json({ error: 'You cannot delete your own admin account.' });
        }
        if (targetUsers[0].role === 'admin' && !await verifyCurrentAdminPassword(req.user.id, req.body?.adminPassword)) {
            return res.status(403).json({ error: 'The admin password is incorrect.' });
        }
        await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
        await logActivity(req.user.id, `Deleted account ID: ${req.params.id}`);
        res.json({ message: 'User deleted' });
    } catch (error) { res.status(500).json({ error: 'Failed to delete user' }); }
});

app.post('/api/register', async (req, res) => {
    const { firstname, lastname, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (firstname, lastname, email, password, role, phone, dob, branch) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)',
            [firstname, lastname, email, hashedPassword, role || 'customer']
        );
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) { res.status(500).json({ error: 'Registration failed or email exists.' }); }
});

app.post('/api/forgot-password', async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Enter a valid email address.' });
    }

    try {
        getBrevoTransport();
        if (!process.env.BREVO_SENDER_EMAIL) throw new Error('BREVO_SENDER_EMAIL is not configured.');
    } catch (error) {
        console.error('Brevo SMTP is not configured:', error.message);
        return res.status(503).json({ error: 'Email service is unavailable. Please try again later.' });
    }

    try {
        const [users] = await pool.execute('SELECT id, email FROM users WHERE email = ? LIMIT 1', [email]);
        if (users.length) {
            const userId = users[0].id;
            const resetToken = crypto.randomBytes(32).toString('hex');
            const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
            await pool.execute(
                'UPDATE users SET password_reset_token_hash = ?, password_reset_expires_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) WHERE id = ?',
                [tokenHash, userId]
            );
            const appUrl = String(process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
            try {
                await sendPasswordResetEmail(email, `${appUrl}/reset-password/${resetToken}`);
            } catch (mailError) {
                await pool.execute('UPDATE users SET password_reset_token_hash = NULL, password_reset_expires_at = NULL WHERE id = ? AND password_reset_token_hash = ?', [userId, tokenHash]);
                console.error('Password reset email could not be sent:', mailError.message);
            }
        }
        // Do not disclose whether the address has an account.
        return res.json({ message: 'If an account exists for that email, a password reset link has been sent.' });
    } catch (error) {
        console.error('Password reset request failed:', error.message);
        return res.status(500).json({ error: 'Could not process the password reset request. Please try again.' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    const token = String(req.body?.token || '');
    const password = req.body?.password;
    if (!/^[a-f0-9]{64}$/i.test(token)) {
        return res.status(400).json({ error: 'This password reset link is invalid or expired.' });
    }
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
        return res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
    }

    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const hashedPassword = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'UPDATE users SET password = ?, password_reset_token_hash = NULL, password_reset_expires_at = NULL WHERE password_reset_token_hash = ? AND password_reset_expires_at > NOW()',
            [hashedPassword, tokenHash]
        );
        if (!result.affectedRows) return res.status(400).json({ error: 'This password reset link is invalid or expired.' });
        return res.json({ message: 'Password reset successfully. You can now sign in.' });
    } catch (error) {
        console.error('Password reset failed:', error.message);
        return res.status(500).json({ error: 'Could not reset the password. Please try again.' });
    }
});

app.post('/api/account-recovery', async (req, res) => {
    const accountName = String(req.body?.accountName || '').trim();
    const accountEmail = String(req.body?.accountEmail || '').trim().toLowerCase();
    const registeredPhone = String(req.body?.registeredPhone || '').trim();
    const registeredDob = String(req.body?.registeredDob || '').trim();
    const newEmail = String(req.body?.newEmail || '').trim().toLowerCase();
    const accountDetails = String(req.body?.accountDetails || '').trim();
    const validEmail = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

    if (!accountName || accountName.length > 255 || !validEmail(accountEmail) || accountEmail.length > 255 || !validEmail(newEmail) || newEmail.length > 255 || accountEmail === newEmail || !registeredPhone || registeredPhone.length > 50 || accountDetails.length > 1000) {
        return res.status(400).json({ error: 'Check the account information and make sure all required fields are valid.' });
    }
    if (registeredDob && !/^\d{4}-\d{2}-\d{2}$/.test(registeredDob)) {
        return res.status(400).json({ error: 'Enter the registered date of birth.' });
    }

    try {
        const [pending] = await pool.execute('SELECT id FROM account_recovery_requests WHERE account_email = ? AND status = "Pending" LIMIT 1', [accountEmail]);
        if (!pending.length) {
            await pool.execute(
                'INSERT INTO account_recovery_requests (account_email, account_name, registered_phone, registered_dob, new_email, account_details) VALUES (?, ?, ?, ?, ?, ?)',
                [accountEmail, accountName, registeredPhone, registeredDob || null, newEmail, accountDetails || null]
            );
        }
        return res.status(201).json({ message: 'Your recovery request was sent for admin review. You will receive an email at the updated address after it is reviewed.' });
    } catch (error) {
        console.error('Account recovery request could not be saved:', error.message);
        return res.status(500).json({ error: 'Could not submit the recovery request. Please try again later.' });
    }
});

app.get('/api/admin/account-recovery', authenticateToken, verifyAdminOnly, async (req, res) => {
    try {
        const [requests] = await pool.execute(`SELECT r.id, r.account_email, r.account_name, r.registered_phone,
            DATE_FORMAT(r.registered_dob, '%Y-%m-%d') AS registered_dob, r.new_email, r.account_details,
            r.status, r.review_note, r.created_at, r.reviewed_at, u.firstname AS reviewer_firstname, u.lastname AS reviewer_lastname,
            account.id AS matched_account_id, account.firstname AS matched_firstname, account.lastname AS matched_lastname,
            account.phone AS matched_phone, DATE_FORMAT(account.dob, '%Y-%m-%d') AS matched_dob
            FROM account_recovery_requests r LEFT JOIN users u ON u.id = r.reviewed_by
            LEFT JOIN users account ON account.email = r.account_email
            ORDER BY CASE WHEN r.status = 'Pending' THEN 0 ELSE 1 END, r.created_at DESC`);
        return res.json(requests);
    } catch (error) {
        console.error('Failed to load account recovery requests:', error.message);
        return res.status(500).json({ error: 'Could not load account recovery requests.' });
    }
});

app.put('/api/admin/account-recovery/:id', authenticateToken, verifyAdminOnly, async (req, res) => {
    const decision = req.body?.decision;
    const adminPassword = req.body?.adminPassword;
    const reviewNote = String(req.body?.reviewNote || '').trim().slice(0, 1000);
    if (!['Approved', 'Denied'].includes(decision)) return res.status(400).json({ error: 'Choose approve or deny.' });
    if (!await verifyCurrentAdminPassword(req.user.id, adminPassword)) return res.status(403).json({ error: 'The admin password is incorrect.' });

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [rows] = await connection.execute('SELECT * FROM account_recovery_requests WHERE id = ? FOR UPDATE', [req.params.id]);
        const request = rows[0];
        if (!request) {
            await connection.rollback();
            return res.status(404).json({ error: 'Recovery request not found.' });
        }
        if (request.status !== 'Pending') {
            await connection.rollback();
            return res.status(409).json({ error: 'This recovery request has already been reviewed.' });
        }

        if (decision === 'Approved') {
            const [accounts] = await connection.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [request.account_email]);
            if (!accounts.length) {
                await connection.rollback();
                return res.status(404).json({ error: 'No account matches the submitted account email. Verify the details before approving.' });
            }
            const accountId = accounts[0].id;
            const [emailConflicts] = await connection.execute('SELECT id FROM users WHERE email = ? AND id <> ? LIMIT 1', [request.new_email, accountId]);
            if (emailConflicts.length) {
                await connection.rollback();
                return res.status(409).json({ error: 'The updated email already belongs to another account.' });
            }

            const resetToken = crypto.randomBytes(32).toString('hex');
            const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
            await connection.execute(
                'UPDATE users SET email = ?, password_reset_token_hash = ?, password_reset_expires_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) WHERE id = ?',
                [request.new_email, tokenHash, accountId]
            );
            const appUrl = String(process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
            await sendRecoveryApprovedEmail(request.new_email, `${appUrl}/reset-password/${resetToken}`);
        } else {
            await sendRecoveryDeniedEmail(request.new_email, reviewNote);
        }

        await connection.execute(
            'UPDATE account_recovery_requests SET status = ?, review_note = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ?',
            [decision, reviewNote || null, req.user.id, request.id]
        );
        await connection.commit();
        await logActivity(req.user.id, `${decision} account recovery request #${request.id}`);
        return res.json({ message: decision === 'Approved' ? 'Recovery approved. A password reset email was sent to the updated address.' : 'Recovery denied. A notice was sent to the updated address.' });
    } catch (error) {
        if (connection) {
            try { await connection.rollback(); } catch (rollbackError) { console.error('Could not roll back account recovery review.'); }
        }
        console.error('Account recovery review failed:', error.message);
        return res.status(503).json({ error: 'Could not complete the review or send its email. The request remains available for review.' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        
        // Log staff logins
        if (user.role !== 'customer') {
            await logActivity(user.id, 'Logged into the system');
        }

        res.json({ 
            token, 
            user: { 
                id: user.id, name: `${user.firstname} ${user.lastname}`, email: user.email, role: user.role, 
                phone: user.phone || '', dob: user.dob || '', branch: user.branch || '', last_updated: user.last_updated || null
            } 
        });
    } catch (error) { res.status(500).json({ error: 'Login failed.' }); }
});

app.post('/api/guest', async (req, res) => {
    try {
        let [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', ['guest@3kkitchen.local']);
        let user;
        if (rows.length === 0) {
            const hashedPassword = await bcrypt.hash('guest123', 10);
            const [result] = await pool.execute(
                'INSERT INTO users (firstname, lastname, email, password, role, phone, dob, branch) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)',
                ['Guest', 'User', 'guest@3kkitchen.local', hashedPassword, 'customer']
            );
            user = { id: result.insertId, role: 'customer', firstname: 'Guest', lastname: 'User', email: 'guest@3kkitchen.local' };
        } else {
            user = rows[0];
        }
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: { id: user.id, name: `${user.firstname} ${user.lastname}`, email: user.email, role: user.role, phone: '', dob: '', branch: '', last_updated: null } });
    } catch (error) {
        console.error('Failed to create kiosk guest session', {
            code: error.code,
            message: error.message
        });
        res.status(500).json({ error: 'Guest login failed.', code: error.code || 'GUEST_SESSION_FAILED' });
    }
});

app.put('/api/users/profile', authenticateToken, async (req, res) => {
    const { email, phone, dob } = req.body;
    const userId = req.user.id;
    try {
        const [rows] = await pool.execute('SELECT last_updated FROM users WHERE id = ?', [userId]);
        const lastUpdated = rows[0].last_updated;
        if (lastUpdated) {
            const thirtyDaysInMs = 30 * 24 * 60 * 60 * 1000;
            const now = new Date();
            const lastUpdateDate = new Date(lastUpdated);
            if (now - lastUpdateDate < thirtyDaysInMs) {
                const daysLeft = Math.ceil((thirtyDaysInMs - (now - lastUpdateDate)) / (1000 * 60 * 60 * 24));
                return res.status(403).json({ error: `You must wait ${daysLeft} more days before updating your profile again.` });
            }
        }
        await pool.execute('UPDATE users SET email = ?, phone = ?, dob = ?, last_updated = NOW() WHERE id = ?', [email, phone, dob || null, userId]);
        res.json({ message: 'Profile updated successfully' });
    } catch (error) { res.status(500).json({ error: 'Failed to update profile' }); }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
    let connection;
    try {
        const { items, totalAmount, orderType, branch, address, phone, paymentMethod, notes, receipt_url } = req.body;
        const { customerName, gcashReference, cashTendered } = req.body;
        const isStaffCounterSale = ['admin', 'cashier'].includes(req.user.role) && ['Dine-in', 'Take-out'].includes(orderType) && (
            customerName !== undefined || gcashReference !== undefined || cashTendered !== undefined
        );
        let isKioskCounterSale = false;
        if (req.user.role === 'customer' && ['Dine-in', 'Take-out'].includes(orderType) && typeof address === 'string' && address.startsWith('Kiosk Customer:')) {
            const [kioskUsers] = await pool.execute('SELECT email FROM users WHERE id = ?', [req.user.id]);
            isKioskCounterSale = kioskUsers[0]?.email === 'guest@3kitchen.local';
        }
        const isCounterSale = isStaffCounterSale || isKioskCounterSale;
        const parsedItems = typeof items === 'string' ? JSON.parse(items) : items;
        if (!Array.isArray(parsedItems) || parsedItems.length === 0) {
            return res.status(400).json({ error: 'Cart is empty' });
        }
        if (!Number.isFinite(Number(totalAmount)) || Number(totalAmount) <= 0) {
            return res.status(400).json({ error: 'Order total is invalid' });
        }
        if (parsedItems.some(item => !item.name || !Number.isFinite(Number(item.qty)) || Number(item.qty) <= 0 || !Number.isFinite(Number(item.price)))) {
            return res.status(400).json({ error: 'One or more cart items are invalid. Please refresh your cart and try again.' });
        }
        if (['Delivery', 'Pick-up'].includes(orderType) && !['GCash', 'Cash on delivery'].includes(paymentMethod)) {
            return res.status(400).json({ error: 'Online orders require GCash or cash on delivery.' });
        }
        if (['Delivery', 'Pick-up'].includes(orderType) && paymentMethod === 'GCash' && !receipt_url) {
            return res.status(400).json({ error: 'Please upload your GCash payment receipt.' });
        }
        if (gcashReference != null && !/^\d{13}$/.test(String(gcashReference))) {
            return res.status(400).json({ error: 'GCash reference number must contain exactly 13 digits.' });
        }
        if (isCounterSale && paymentMethod === 'GCash' && !/^\d{13}$/.test(String(gcashReference || ''))) {
            return res.status(400).json({ error: 'Enter a valid 13-digit GCash reference number.' });
        }
        if (isCounterSale && !['Cash', 'GCash'].includes(paymentMethod)) {
            return res.status(400).json({ error: 'Counter sales must be paid by cash or GCash.' });
        }
        if (isCounterSale && paymentMethod === 'Cash' && (!Number.isFinite(Number(cashTendered)) || Number(cashTendered) < Number(totalAmount))) {
            return res.status(400).json({ error: 'Cash tendered must cover the order total.' });
        }
        if (typeof customerName === 'string' && customerName.trim().length > 255) {
            return res.status(400).json({ error: 'Customer calling name must be 255 characters or fewer.' });
        }
        if (customerName !== undefined && typeof customerName !== 'string') {
            return res.status(400).json({ error: 'Customer calling name must be text.' });
        }

        const callingName = isCounterSale ? (String(customerName || '').trim() || 'Walk-in Customer') : null;
        const tenderedAmount = isCounterSale && paymentMethod === 'Cash' ? Number(cashTendered) : null;
        const changeAmount = tenderedAmount === null ? null : tenderedAmount - Number(totalAmount);

        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [orderResult] = await connection.execute(
            `INSERT INTO orders (user_id, total_amount, order_type, branch, delivery_address, contact_number, payment_method, gcash_receipt_url, notes, customer_name, gcash_reference, cash_tendered, change_given) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [req.user.id, totalAmount, orderType, branch, address || null, phone || null, paymentMethod, receipt_url || null, notes || null, callingName, isCounterSale && paymentMethod === 'GCash' ? gcashReference : null, tenderedAmount, changeAmount]
        );
        for (const item of parsedItems) {
            await connection.execute('INSERT INTO order_items (order_id, item_name, quantity, price) VALUES (?, ?, ?, ?)', [orderResult.insertId, item.name, item.qty, parseFloat(item.price)]);
        }
        await connection.commit();
        
        await logActivity(req.user.id, `Placed new order O-${String(orderResult.insertId).padStart(4, '0')}`);
        
        io.emit('dashboard_refresh'); 
        res.status(201).json({ message: 'Order placed', orderId: orderResult.insertId });
    } catch (error) {
        if (connection) {
            try { await connection.rollback(); } catch (rollbackError) {
                console.error('Failed to roll back order transaction', rollbackError);
            }
        }
        console.error('Failed to place order', {
            code: error.code,
            message: error.message,
            userId: req.user?.id
        });
        res.status(500).json({
            error: 'We could not save this order. Please try again.',
            code: error.code || 'ORDER_CREATE_FAILED'
        });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const [orders] = await pool.execute(`SELECT *, UNIX_TIMESTAMP(chat_expires_at) * 1000 AS chat_expires_at_ms
            FROM orders WHERE user_id = ? ORDER BY created_at DESC`, [req.user.id]);
        for (let order of orders) {
            const [items] = await pool.execute("SELECT item_name as name, quantity as qty, price FROM order_items WHERE order_id = ?", [order.id]);
            order.items = items;
            order.date = new Date(order.created_at).toLocaleString();
        }
        res.json(orders);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch user orders' }); }
});

app.get('/api/admin/orders', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [orders] = await pool.execute(`SELECT o.*, UNIX_TIMESTAMP(o.chat_expires_at) * 1000 AS chat_expires_at_ms,
            u.firstname, u.lastname, u.email FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC`);
        for (let order of orders) {
            const [items] = await pool.execute("SELECT item_name as name, quantity as qty, price FROM order_items WHERE order_id = ?", [order.id]);
            order.itemsData = items;
            order.items = items.map(i => `${i.qty}x ${i.name}`).join(', ');
            order.date = new Date(order.created_at).toLocaleString();
            order.customerName = `${order.firstname} ${order.lastname}`;
        }
        res.json(orders);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch orders' }); }
});

app.put('/api/admin/orders/:id/status', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute(`UPDATE orders SET status = ?, chat_expires_at = CASE
            WHEN ? = 'Completed' THEN CASE
                WHEN status = 'Completed' AND chat_expires_at IS NOT NULL THEN chat_expires_at
                ELSE DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 10 MINUTE)
            END
            ELSE NULL
        END WHERE id = ?`, [req.body.status, req.body.status, req.params.id]);
        await logActivity(req.user.id, `Updated order O-${String(req.params.id).padStart(4, '0')} status to ${req.body.status}`);
        
        io.emit('dashboard_refresh'); 
        res.json({ message: 'Status updated' });
    } catch (error) { res.status(500).json({ error: 'Failed to update status' }); }
});

app.put('/api/admin/orders/:id/payment', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const { paymentMethod, cashTendered, gcashReference } = req.body;
        const [existingOrders] = await pool.execute('SELECT total_amount FROM orders WHERE id = ?', [req.params.id]);
        if (!existingOrders.length) return res.status(404).json({ error: 'Order not found' });
        if (gcashReference != null && !/^\d{13}$/.test(String(gcashReference))) {
            return res.status(400).json({ error: 'GCash reference number must contain exactly 13 digits.' });
        }

        let tenderedAmount = null;
        let changeAmount = null;
        if (paymentMethod === 'Cash' && cashTendered != null) {
            tenderedAmount = Number(cashTendered);
            if (!Number.isFinite(tenderedAmount) || tenderedAmount < Number(existingOrders[0].total_amount)) {
                return res.status(400).json({ error: 'Cash tendered must cover the order total.' });
            }
            changeAmount = tenderedAmount - Number(existingOrders[0].total_amount);
        }

        await pool.execute(
            'UPDATE orders SET payment_method = ?, cash_tendered = ?, change_given = ?, gcash_reference = ? WHERE id = ?',
            [paymentMethod, tenderedAmount, changeAmount, paymentMethod === 'GCash' ? gcashReference || null : null, req.params.id]
        );
        const [orders] = await pool.execute('SELECT payment_method, cash_tendered, change_given, gcash_reference FROM orders WHERE id = ?', [req.params.id]);
        if (!orders.length) return res.status(404).json({ error: 'Order not found' });
        if (orders[0]?.payment_method !== paymentMethod) {
            return res.status(500).json({ error: 'Payment method was not saved' });
        }

        await logActivity(req.user.id, `Processed payment for order O-${String(req.params.id).padStart(4, '0')}`);
        
        io.emit('dashboard_refresh'); 
        res.json({ message: 'Payment method updated' });
    } catch (error) {
        console.error('Failed to update payment method', error);
        res.status(500).json({ error: 'Failed to update payment method' });
    }
});

app.get('/api/menu', async (req, res) => {
    try {
        const [items] = await pool.execute('SELECT * FROM menu_items ORDER BY category, name');
        res.json(items);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch menu' }); }
});

app.get('/api/menu/best-sellers', async (req, res) => {
    try {
        const [items] = await pool.execute(`
            SELECT m.*, sales.total_sold
            FROM menu_items m
            LEFT JOIN (
                SELECT oi.item_name, SUM(oi.quantity) AS total_sold
                FROM order_items oi
                INNER JOIN orders o ON o.id = oi.order_id
                WHERE o.status <> 'Cancelled'
                GROUP BY oi.item_name
            ) sales ON LOWER(TRIM(sales.item_name)) = LOWER(TRIM(m.name))
            WHERE COALESCE(m.is_sold_out, 0) = 0
            ORDER BY COALESCE(sales.total_sold, 0) DESC, m.name ASC
            LIMIT 3
        `);
        res.json(items);
    } catch (error) {
        console.error('Failed to fetch menu best sellers', error);
        res.status(500).json({ error: 'Failed to fetch best sellers' });
    }
});

app.post('/api/admin/menu', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('INSERT INTO menu_items (name, category, price, image_url) VALUES (?, ?, ?, ?)', [req.body.name, req.body.category, req.body.price, req.body.image_url || '/img/default-food.jpg']);
        await logActivity(req.user.id, `Added new menu item: ${req.body.name}`);
        res.status(201).json({ message: 'Item added' });
    } catch (error) { res.status(500).json({ error: 'Failed to add item' }); }
});

app.put('/api/admin/menu/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        if (req.body.image_url) {
            await pool.execute('UPDATE menu_items SET name = ?, category = ?, price = ?, image_url = ? WHERE id = ?', [req.body.name, req.body.category, req.body.price, req.body.image_url, req.params.id]);
        } else {
            await pool.execute('UPDATE menu_items SET name = ?, category = ?, price = ? WHERE id = ?', [req.body.name, req.body.category, req.body.price, req.params.id]);
        }
        await logActivity(req.user.id, `Updated menu item: ${req.body.name}`);
        res.json({ message: 'Item updated' });
    } catch (error) { res.status(500).json({ error: 'Failed to update item' }); }
});

app.put('/api/admin/menu/:id/stock', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('UPDATE menu_items SET is_sold_out = ? WHERE id = ?', [req.body.is_sold_out, req.params.id]);
        await logActivity(req.user.id, `Updated stock status for item ID: ${req.params.id}`);
        res.json({ message: 'Stock updated' });
    } catch (error) { res.status(500).json({ error: 'Failed to update stock' }); }
});

app.delete('/api/admin/menu/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('DELETE FROM menu_items WHERE id = ?', [req.params.id]);
        await logActivity(req.user.id, `Deleted menu item ID: ${req.params.id}`);
        res.json({ message: 'Item deleted' });
    } catch (error) { res.status(500).json({ error: 'Failed to delete item' }); }
});

app.get('/api/branches', async (req, res) => {
    try {
        const [branches] = await pool.execute('SELECT * FROM branches ORDER BY name');
        res.json(branches);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch branches' }); }
});

app.post('/api/admin/branches', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('INSERT INTO branches (name, code, address, phone) VALUES (?, ?, ?, ?)', [req.body.name, req.body.code, req.body.address, req.body.phone]);
        await logActivity(req.user.id, `Created new branch: ${req.body.name}`);
        res.status(201).json({ message: 'Branch added' });
    } catch (error) { res.status(500).json({ error: 'Failed to add branch' }); }
});

app.put('/api/admin/branches/:id/status', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('UPDATE branches SET is_active = ? WHERE id = ?', [req.body.is_active, req.params.id]);
        await logActivity(req.user.id, `Updated branch status for ID: ${req.params.id}`);
        res.json({ message: 'Branch status updated' });
    } catch (error) { res.status(500).json({ error: 'Failed to update branch' }); }
});

app.get('/api/admin/riders', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [riders] = await pool.execute('SELECT id, firstname, lastname, email, created_at FROM users WHERE role = "rider"');
        res.json(riders);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch riders' }); }
});

app.get('/api/orders/:id/chat', authenticateToken, async (req, res) => {
    try {
        await pool.execute(`CREATE TABLE IF NOT EXISTS order_chats (id INT AUTO_INCREMENT PRIMARY KEY, order_id INT NOT NULL, sender VARCHAR(255) NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE)`);
        const [messages] = await pool.execute('SELECT sender, message as text, DATE_FORMAT(created_at, "%h:%i %p") as time FROM order_chats WHERE order_id = ? ORDER BY created_at ASC', [req.params.id]);
        res.json(messages);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch chat history' }); }
});

const PORT = process.env.PORT || 5000;
databaseReady
    .then(() => server.listen(PORT, () => console.log(`Server running on port ${PORT}`)))
    .catch(error => {
        console.error('Database initialization failed. Server was not started.', error);
        process.exitCode = 1;
    });
