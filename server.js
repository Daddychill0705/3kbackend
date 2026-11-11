const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const net = require('net');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();

app.set('trust proxy', 1);
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
    return nodemailer.createTransport({
        host,
        port,
        secure: port === 465,
        auth: { user, pass },
        connectionTimeout: 15000,
        greetingTimeout: 10000,
        socketTimeout: 30000
    });
};

const sendAppEmail = async ({ to, subject, text, html }) => {
    const fromEmail = process.env.BREVO_SENDER_EMAIL;
    if (!fromEmail) throw new Error('BREVO_SENDER_EMAIL is not configured.');
    const fromName = process.env.BREVO_SENDER_NAME || '3K Kitchen';
    if (process.env.BREVO_API_KEY) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 20000);
        try {
            const response = await fetch('https://api.brevo.com/v3/smtp/email', {
                method: 'POST',
                headers: {
                    accept: 'application/json',
                    'api-key': process.env.BREVO_API_KEY,
                    'content-type': 'application/json'
                },
                body: JSON.stringify({
                    sender: { name: fromName, email: fromEmail },
                    to: (Array.isArray(to) ? to : [to]).map(recipient => typeof recipient === 'string' ? { email: recipient } : recipient),
                    subject,
                    textContent: text,
                    htmlContent: html
                }),
                signal: controller.signal
            });
            const result = await response.json().catch(() => ({}));
            if (!response.ok) {
                const reason = result.message || result.code || `HTTP ${response.status}`;
                throw new Error(`Brevo API send failed: ${reason}`);
            }
            return result;
        } finally {
            clearTimeout(timeout);
        }
    }

    const transporter = getBrevoTransport();
    return transporter.sendMail({
        from: { name: fromName, address: fromEmail },
        to,
        subject,
        text,
        html
    });
};

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

const makeOtpHash = (email, purpose, otp) => crypto.createHmac('sha256', process.env.JWT_SECRET || '3k-kitchen-otp')
    .update(`${purpose}:${email}:${otp}`).digest('hex');

const sendOtpEmail = async (email, otp, purpose) => {
    const registration = purpose === 'register';
    const heading = registration ? 'Verify your 3K Kitchen account' : 'Reset your 3K Kitchen password';
    const description = registration
        ? 'Enter this verification code to finish creating your account.'
        : 'Enter this verification code to reset your password.';
    await sendAppEmail({
        to: email,
        subject: registration ? 'Your 3K Kitchen sign-up code' : 'Your 3K Kitchen password reset code',
        text: `${heading}\n\n${description}\n\nYour code is ${otp}. It expires in 10 minutes. If you did not request this, you can ignore this email.`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>${heading}</h1><p>${description}</p><p style="font-size:30px;font-weight:bold;letter-spacing:8px;color:#815633">${otp}</p><p>This code expires in 10 minutes. If you did not request this, you can ignore this email.</p></div>`
    });
};

const sendAccountCreatedEmail = async email => sendAppEmail({
    to: email,
    subject: 'Welcome to 3K Kitchen',
    text: 'Your 3K Kitchen account is ready. You can now sign in. If you did not create this account, contact 3K Kitchen support.',
    html: '<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>Welcome to 3K Kitchen!</h1><p>Your account is ready. You can now sign in.</p><p>If you did not create this account, contact 3K Kitchen support.</p></div>'
});

const isPublicIp = ip => {
    const normalized = String(ip || '').replace(/^::ffff:/i, '');
    const version = net.isIP(normalized);
    if (version === 4) {
        const parts = normalized.split('.').map(Number);
        return !(parts[0] === 10 || parts[0] === 127 || parts[0] === 0 ||
            (parts[0] === 169 && parts[1] === 254) ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === 192 && parts[1] === 168) || parts[0] >= 224);
    }
    if (version === 6) return !(/^::1$|^fc|^fd|^fe80:/i.test(normalized));
    return false;
};

const getApproximateIpLocation = async ip => {
    if (!isPublicIp(ip)) return 'Unavailable (local or private network)';
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    try {
        const response = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, { signal: controller.signal });
        if (!response.ok) return 'Unavailable';
        const data = await response.json();
        return [data.city, data.region, data.country_name].filter(Boolean).join(', ') || 'Unavailable';
    } catch (_) {
        return 'Unavailable';
    } finally {
        clearTimeout(timeout);
    }
};

const sendLoginAlert = async (user, ip) => {
    const location = await getApproximateIpLocation(ip);
    const signedInAt = new Date().toLocaleString('en-PH', { timeZone: 'Asia/Manila', dateStyle: 'medium', timeStyle: 'long' });
    await sendAppEmail({
        to: user.email,
        subject: 'New sign-in to your 3K Kitchen account',
        text: `A sign-in to your 3K Kitchen account was detected.\n\nTime: ${signedInAt}\nApproximate location: ${location}\nIP address: ${ip || 'Unavailable'}\n\nIf this was not you, reset your password and contact an administrator.`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>New sign-in detected</h1><p>A sign-in to your 3K Kitchen account was detected.</p><p><b>Time:</b> ${escapeHtml(signedInAt)}<br><b>Approximate location:</b> ${escapeHtml(location)}<br><b>IP address:</b> ${escapeHtml(ip || 'Unavailable')}</p><p>If this was not you, reset your password and contact an administrator.</p></div>`
    });
};

const sendOnlineOrderEmails = async ({ orderId, userId, orderType, branch, totalAmount, paymentMethod, items }) => {
    const [customers] = await pool.execute('SELECT firstname, lastname, email FROM users WHERE id = ? LIMIT 1', [userId]);
    const customer = customers[0];
    if (!customer || customer.email === 'guest@3kkitchen.local') return;
    const orderNumber = `O-${String(orderId).padStart(4, '0')}`;
    const lines = items.map(item => `${item.qty}x ${item.name} — PHP ${Number(item.price) * Number(item.qty)}`).join('\n');
    const details = `Order ${orderNumber}\nCustomer: ${customer.firstname} ${customer.lastname}\nType: ${orderType}\nBranch: ${branch || 'Not specified'}\nPayment: ${paymentMethod || 'Not specified'}\nTotal: PHP ${Number(totalAmount).toFixed(2)}\n\n${lines}`;
    const htmlItems = items.map(item => `<li>${escapeHtml(item.qty)}x ${escapeHtml(item.name)} — PHP ${(Number(item.price) * Number(item.qty)).toFixed(2)}</li>`).join('');
    const baseHtml = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>Order ${escapeHtml(orderNumber)}</h1><p><b>Customer:</b> ${escapeHtml(customer.firstname)} ${escapeHtml(customer.lastname)}<br><b>Type:</b> ${escapeHtml(orderType)}<br><b>Branch:</b> ${escapeHtml(branch || 'Not specified')}<br><b>Payment:</b> ${escapeHtml(paymentMethod || 'Not specified')}<br><b>Total:</b> PHP ${Number(totalAmount).toFixed(2)}</p><ul>${htmlItems}</ul></div>`;
    const notifications = [];
    notifications.push(sendAppEmail({ to: customer.email, subject: `3K Kitchen received your order ${orderNumber}`, text: `Your online order has been received. The kitchen will prepare it shortly.\n\n${details}`, html: `<p>Your online order has been received. The kitchen will prepare it shortly.</p>${baseHtml}` }));
    const [staff] = await pool.execute('SELECT email FROM users WHERE role IN ("admin", "cashier") AND email IS NOT NULL AND email <> ""');
    for (const member of staff) {
        notifications.push(sendAppEmail({ to: member.email, subject: `New online order ${orderNumber}`, text: `A new online order is waiting for staff review.\n\n${details}`, html: `<p>A new online order is waiting for staff review.</p>${baseHtml}` }));
    }
    const results = await Promise.allSettled(notifications);
    for (const result of results) if (result.status === 'rejected') console.error('Order email notification failed:', result.reason?.message || 'email error');
};

const sendPasswordResetEmail = async (email, resetUrl) => {
    await sendAppEmail({
        to: email,
        subject: 'Reset your 3K Kitchen password',
        text: `We received a request to reset your 3K Kitchen password. Open this link within 30 minutes to choose a new password: ${resetUrl}\n\nIf you did not request this, you can ignore this email.`,
        html: `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>Reset your password</h1><p>We received a request to reset your 3K Kitchen password.</p><p><a href="${resetUrl}" style="display:inline-block;padding:12px 20px;background:#815633;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold">Choose a new password</a></p><p>This link expires in 30 minutes. If you did not request this, you can ignore this email.</p></div>`
    });
};

const sendRecoveryDeniedEmail = async (email, note = '') => {
    const decisionText = `Your 3K Kitchen account recovery request was denied.${note ? ` Admin note: ${note}` : ''}`;
    await sendAppEmail({
        to: email,
        subject: '3K Kitchen account recovery update',
        text: `${decisionText}\n\nIf you did not submit this request, contact 3K Kitchen support.`
    });
};

const sendRecoveryApprovedEmail = async (email, resetUrl) => {
    await sendAppEmail({
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

    try {
        await pool.execute(`CREATE TABLE IF NOT EXISTS email_otp_challenges (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            purpose VARCHAR(32) NOT NULL,
            code_hash CHAR(64) NOT NULL,
            reset_token_hash CHAR(64) DEFAULT NULL,
            payload TEXT DEFAULT NULL,
            attempts INT NOT NULL DEFAULT 0,
            expires_at DATETIME NOT NULL,
            consumed_at DATETIME DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_email_otp_email_purpose (email, purpose, created_at)
        )`);
    } catch (e) { console.error('Failed to create email_otp_challenges table', e); }
    try {
        await pool.execute('ALTER TABLE email_otp_challenges ADD COLUMN reset_token_hash CHAR(64) DEFAULT NULL');
    } catch (_) { /* Column already exists. */ }

    try {
        await pool.execute(`CREATE TABLE IF NOT EXISTS menu_categories (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(120) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`);
        await pool.execute(`INSERT IGNORE INTO menu_categories (name)
            SELECT DISTINCT TRIM(category) FROM menu_items
            WHERE category IS NOT NULL AND TRIM(category) <> ''`);
    } catch (error) { console.error('Failed to prepare menu categories:', error.message); }

    const requestedBranches = [
        { name: 'Dasma Langkaan Branch', code: 'DASMA-LANGKAAN', address: '0680 ME Juanito R. Remulla Sr. Road, Langkaan I, Dasmariñas, Cavite', aliases: ['dasma langkaan', 'langkaan'] },
        { name: 'Gentry Branch', code: 'GENTRY', address: 'Mel-Gus Bldg, Juanito R. Remulla Senior Rd, General Trias, 4107 Cavite', aliases: ['gentry', 'general trias'] },
        { name: 'Trece Martires Branch', code: 'TRECE-MARTIRES', address: '7VGC+M5P, Trece Martires City, Cavite', aliases: ['trece martires', 'trece'] },
        { name: 'Imus Branch', code: 'IMUS', address: 'Plaza Homes Subdivision, Imus, Cavite', aliases: ['imus'] },
        { name: 'Dasma Bayan Branch', code: 'DASMA-BAYAN', address: '79 Don Placido Campos Avenue, San Agustin III, Dasmariñas, 4114 Cavite', aliases: ['dasma bayan'] }
    ];
    try {
        const [existingBranches] = await pool.execute('SELECT id, name, code FROM branches');
        const normalizeBranchName = value => String(value || '').toLowerCase().replace(/\b(branch|br)\b/g, '').replace(/[^a-z0-9]/g, '');
        for (const requested of requestedBranches) {
            const match = existingBranches.find(branch => requested.aliases.some(alias => {
                const aliasKey = normalizeBranchName(alias);
                return normalizeBranchName(branch.name).includes(aliasKey);
            }));
            if (match) {
                // Preserve the existing branch name/code/status and update only its address.
                await pool.execute('UPDATE branches SET address = ? WHERE id = ?', [requested.address, match.id]);
                continue;
            }
            let code = requested.code;
            let suffix = 2;
            while (existingBranches.some(branch => String(branch.code || '').toLowerCase() === code.toLowerCase())) {
                code = `${requested.code}-${suffix++}`;
            }
            const [inserted] = await pool.execute(
                'INSERT INTO branches (name, code, address, phone) VALUES (?, ?, ?, NULL)',
                [requested.name, code, requested.address]
            );
            existingBranches.push({ id: inserted.insertId, name: requested.name, code });
        }
    } catch (error) {
        console.error('Failed to update requested branch addresses:', error.message);
    }
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
        sendAccountCreatedEmail(email).catch(mailError => console.error('Staff account-created email failed:', mailError.message));
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

app.post('/api/register', (req, res) => res.status(410).json({ error: 'Email verification is required. Request a sign-up code to create an account.' }));

app.post('/api/register/request-otp', async (req, res) => {
    const firstname = String(req.body?.firstname || '').trim();
    const lastname = String(req.body?.lastname || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = req.body?.password;
    if (!firstname || firstname.length > 100 || !lastname || lastname.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255 || typeof password !== 'string' || password.length < 8 || password.length > 128 || req.body?.termsAccepted !== true) {
        return res.status(400).json({ error: 'Enter valid account details, use a password of at least 8 characters, and accept the Terms and Privacy Policy.' });
    }
    try {
        const [existing] = await pool.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
        if (existing.length) return res.status(409).json({ error: 'An account already uses this email address.' });
        const [recent] = await pool.execute('SELECT id FROM email_otp_challenges WHERE email = ? AND purpose = "register" AND created_at > DATE_SUB(NOW(), INTERVAL 60 SECOND) LIMIT 1', [email]);
        if (recent.length) return res.status(429).json({ error: 'Please wait one minute before requesting another code.' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const payload = JSON.stringify({ firstname, lastname, email, password: hashedPassword });
        const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
        await pool.execute('UPDATE email_otp_challenges SET consumed_at = NOW() WHERE email = ? AND purpose = "register" AND consumed_at IS NULL', [email]);
        const [inserted] = await pool.execute(
            'INSERT INTO email_otp_challenges (email, purpose, code_hash, payload, expires_at) VALUES (?, "register", ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
            [email, makeOtpHash(email, 'register', otp), payload]
        );
        try {
            await sendOtpEmail(email, otp, 'register');
        } catch (mailError) {
            await pool.execute('DELETE FROM email_otp_challenges WHERE id = ?', [inserted.insertId]);
            console.error('Registration OTP email failed:', mailError.message);
            return res.status(503).json({ error: 'Could not send the verification email. Please try again later.' });
        }
        return res.json({ message: 'A verification code was sent to your email. It expires in 10 minutes.' });
    } catch (error) {
        console.error('Registration OTP request failed:', error.message);
        return res.status(500).json({ error: 'Could not start account registration. Please try again.' });
    }
});

app.post('/api/register/verify-otp', async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const otp = String(req.body?.otp || '').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(otp)) return res.status(400).json({ error: 'Enter the email address and 6-digit verification code.' });
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [challenges] = await connection.execute('SELECT * FROM email_otp_challenges WHERE email = ? AND purpose = "register" AND consumed_at IS NULL AND expires_at > NOW() ORDER BY id DESC LIMIT 1 FOR UPDATE', [email]);
        const challenge = challenges[0];
        if (!challenge || challenge.attempts >= 5) {
            await connection.rollback();
            return res.status(400).json({ error: 'The verification code is invalid or expired. Request a new code.' });
        }
        if (!crypto.timingSafeEqual(Buffer.from(challenge.code_hash), Buffer.from(makeOtpHash(email, 'register', otp)))) {
            await connection.execute('UPDATE email_otp_challenges SET attempts = attempts + 1 WHERE id = ?', [challenge.id]);
            await connection.commit();
            return res.status(400).json({ error: 'The verification code is incorrect.' });
        }
        const account = JSON.parse(challenge.payload || '{}');
        const [existing] = await connection.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
        if (existing.length) {
            await connection.rollback();
            return res.status(409).json({ error: 'An account already uses this email address.' });
        }
        await connection.execute(
            'INSERT INTO users (firstname, lastname, email, password, role, phone, dob, branch) VALUES (?, ?, ?, ?, "customer", NULL, NULL, NULL)',
            [account.firstname, account.lastname, email, account.password]
        );
        await connection.execute('UPDATE email_otp_challenges SET consumed_at = NOW() WHERE id = ?', [challenge.id]);
        await connection.commit();
        sendAccountCreatedEmail(email).catch(mailError => console.error('Account-created email failed:', mailError.message));
        return res.status(201).json({ message: 'Your account has been verified and created. You can now sign in.' });
    } catch (error) {
        if (connection) try { await connection.rollback(); } catch (_) {}
        console.error('Registration OTP verification failed:', error.message);
        return res.status(500).json({ error: 'Could not verify the account. Please try again.' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/forgot-password/request-otp', async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 255) return res.status(400).json({ error: 'Enter a valid email address.' });
    try {
        const [users] = await pool.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
        // Use the same response for known and unknown addresses to avoid account enumeration.
        if (!users.length) return res.json({ message: 'If an account exists for that email, a reset code has been sent.' });
        const [recent] = await pool.execute('SELECT id FROM email_otp_challenges WHERE email = ? AND purpose = "reset" AND created_at > DATE_SUB(NOW(), INTERVAL 60 SECOND) LIMIT 1', [email]);
        if (recent.length) return res.status(429).json({ error: 'Please wait one minute before requesting another code.' });
        const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
        await pool.execute('UPDATE email_otp_challenges SET consumed_at = NOW() WHERE email = ? AND purpose = "reset" AND consumed_at IS NULL', [email]);
        const [inserted] = await pool.execute(
            'INSERT INTO email_otp_challenges (email, purpose, code_hash, expires_at) VALUES (?, "reset", ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
            [email, makeOtpHash(email, 'reset', otp)]
        );
        try {
            await sendOtpEmail(email, otp, 'reset');
        } catch (mailError) {
            await pool.execute('DELETE FROM email_otp_challenges WHERE id = ?', [inserted.insertId]);
            console.error('Password reset OTP email failed:', mailError.message);
            return res.status(503).json({ error: 'Could not send the verification email. Please try again later.' });
        }
        return res.json({ message: 'If an account exists for that email, a reset code has been sent.' });
    } catch (error) {
        console.error('Password reset OTP request failed:', error.message);
        return res.status(500).json({ error: 'Could not process the password reset request.' });
    }
});

app.post('/api/forgot-password/verify-otp', async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const otp = String(req.body?.otp || '').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(otp)) return res.status(400).json({ error: 'Enter a valid email and 6-digit verification code.' });
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [challenges] = await connection.execute('SELECT * FROM email_otp_challenges WHERE email = ? AND purpose = "reset" AND consumed_at IS NULL AND expires_at > NOW() ORDER BY id DESC LIMIT 1 FOR UPDATE', [email]);
        const challenge = challenges[0];
        if (!challenge || challenge.attempts >= 5) {
            await connection.rollback();
            return res.status(400).json({ error: 'The verification code is invalid or expired. Request a new code.' });
        }
        if (!crypto.timingSafeEqual(Buffer.from(challenge.code_hash), Buffer.from(makeOtpHash(email, 'reset', otp)))) {
            await connection.execute('UPDATE email_otp_challenges SET attempts = attempts + 1 WHERE id = ?', [challenge.id]);
            await connection.commit();
            return res.status(400).json({ error: 'The verification code is incorrect.' });
        }
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        await connection.execute(
            'UPDATE email_otp_challenges SET reset_token_hash = ?, expires_at = DATE_ADD(NOW(), INTERVAL 10 MINUTE) WHERE id = ?',
            [resetTokenHash, challenge.id]
        );
        await connection.commit();
        return res.json({ message: 'Email verified. Choose a new password to finish resetting your account.', resetToken });
    } catch (error) {
        if (connection) try { await connection.rollback(); } catch (_) {}
        console.error('Password reset OTP verification failed:', error.message);
        return res.status(500).json({ error: 'Could not reset the password. Please try again.' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/forgot-password/reset-with-token', async (req, res) => {
    const resetToken = String(req.body?.resetToken || '');
    const password = req.body?.password;
    if (!/^[a-f0-9]{64}$/i.test(resetToken) || typeof password !== 'string' || password.length < 8 || password.length > 128) {
        return res.status(400).json({ error: 'Enter a valid reset session and password of at least 8 characters.' });
    }
    let connection;
    try {
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        const hashedPassword = await bcrypt.hash(password, 10);
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [challenges] = await connection.execute(
            'SELECT id, email FROM email_otp_challenges WHERE purpose = "reset" AND reset_token_hash = ? AND consumed_at IS NULL AND expires_at > NOW() ORDER BY id DESC LIMIT 1 FOR UPDATE',
            [resetTokenHash]
        );
        const challenge = challenges[0];
        if (!challenge) {
            await connection.rollback();
            return res.status(400).json({ error: 'Your verification session expired. Request a new code.' });
        }
        const [updatedUser] = await connection.execute(
            'UPDATE users SET password = ?, password_reset_token_hash = NULL, password_reset_expires_at = NULL WHERE email = ?',
            [hashedPassword, challenge.email]
        );
        if (!updatedUser.affectedRows) {
            await connection.rollback();
            return res.status(400).json({ error: 'Your verification session expired. Request a new code.' });
        }
        await connection.execute('UPDATE email_otp_challenges SET consumed_at = NOW(), reset_token_hash = NULL WHERE id = ?', [challenge.id]);
        await connection.commit();
        sendAppEmail({ to: challenge.email, subject: 'Your 3K Kitchen password was changed', text: 'The password for your 3K Kitchen account was changed. If you did not make this change, contact an administrator.', html: '<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>Password changed</h1><p>The password for your 3K Kitchen account was changed.</p><p>If you did not make this change, contact an administrator.</p></div>' }).catch(mailError => console.error('Password change notice email failed:', mailError.message));
        return res.json({ message: 'Password reset successfully. You can now sign in.' });
    } catch (error) {
        if (connection) try { await connection.rollback(); } catch (_) {}
        console.error('Password reset completion failed:', error.message);
        return res.status(500).json({ error: 'Could not reset the password. Please try again.' });
    } finally {
        if (connection) connection.release();
    }
});

app.post('/api/forgot-password', async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ error: 'Enter a valid email address.' });
    }

    try {
        if (!process.env.BREVO_API_KEY) getBrevoTransport();
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
        const [matchingUsers] = await pool.execute('SELECT email FROM users WHERE password_reset_token_hash = ? AND password_reset_expires_at > NOW() LIMIT 1', [tokenHash]);
        const [result] = await pool.execute(
            'UPDATE users SET password = ?, password_reset_token_hash = NULL, password_reset_expires_at = NULL WHERE password_reset_token_hash = ? AND password_reset_expires_at > NOW()',
            [hashedPassword, tokenHash]
        );
        if (!result.affectedRows) return res.status(400).json({ error: 'This password reset link is invalid or expired.' });
        if (matchingUsers[0]?.email) {
            sendAppEmail({ to: matchingUsers[0].email, subject: 'Your 3K Kitchen password was changed', text: 'The password for your 3K Kitchen account was changed. If you did not make this change, contact an administrator.', html: '<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#33251b"><h1>Password changed</h1><p>The password for your 3K Kitchen account was changed.</p><p>If you did not make this change, contact an administrator.</p></div>' }).catch(mailError => console.error('Password change notice email failed:', mailError.message));
        }
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

        const loginIp = String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/i, '') || 'Unavailable';
        sendLoginAlert(user, loginIp).catch(mailError => console.error('Login alert email failed:', mailError.message));

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

        if (['Delivery', 'Pick-up'].includes(orderType)) {
            sendOnlineOrderEmails({
                orderId: orderResult.insertId,
                userId: req.user.id,
                orderType,
                branch,
                totalAmount,
                paymentMethod,
                items: parsedItems
            }).catch(mailError => console.error('Online order email notification failed:', mailError.message));
        }
        
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

app.get('/api/menu/categories', async (req, res) => {
    try {
        const [categories] = await pool.execute('SELECT id, name FROM menu_categories ORDER BY name');
        res.json(categories);
    } catch (error) {
        console.error('Failed to fetch menu categories:', error.message);
        res.status(500).json({ error: 'Failed to fetch menu categories.' });
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

app.post('/api/admin/menu/categories', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const name = String(req.body?.name || '').trim().replace(/\s+/g, ' ');
    if (!name || name.length > 120) return res.status(400).json({ error: 'Category name must be between 1 and 120 characters.' });
    try {
        const [result] = await pool.execute('INSERT INTO menu_categories (name) VALUES (?)', [name]);
        await logActivity(req.user.id, `Added menu category: ${name}`);
        io.emit('dashboard_refresh');
        res.status(201).json({ id: result.insertId, name });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'That category already exists.' });
        console.error('Failed to add menu category:', error.message);
        res.status(500).json({ error: 'Failed to add menu category.' });
    }
});

app.delete('/api/admin/menu/categories', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const name = String(req.body?.name || '').trim();
    const moveTo = String(req.body?.moveTo || '').trim();
    if (!name) return res.status(400).json({ error: 'Choose a category to delete.' });
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [categories] = await connection.execute('SELECT id, name FROM menu_categories WHERE name = ? LIMIT 1 FOR UPDATE', [name]);
        if (!categories.length) {
            await connection.rollback();
            return res.status(404).json({ error: 'Category not found.' });
        }

        const [products] = await connection.execute('SELECT COUNT(*) AS count FROM menu_items WHERE category = ?', [name]);
        const productCount = Number(products[0]?.count || 0);
        if (productCount > 0 && (!moveTo || moveTo === name)) {
            await connection.rollback();
            return res.status(409).json({ error: 'Choose another category to move the products into before deleting this category.' });
        }
        if (productCount > 0) {
            const [targetCategories] = await connection.execute('SELECT id FROM menu_categories WHERE name = ? LIMIT 1', [moveTo]);
            if (!targetCategories.length) {
                await connection.rollback();
                return res.status(400).json({ error: 'The destination category is not available.' });
            }
            await connection.execute('UPDATE menu_items SET category = ? WHERE category = ?', [moveTo, name]);
        }

        await connection.execute('DELETE FROM menu_categories WHERE id = ?', [categories[0].id]);
        await connection.commit();
        await logActivity(req.user.id, `Deleted menu category: ${name}${productCount > 0 ? ` and moved ${productCount} product${productCount === 1 ? '' : 's'} to ${moveTo}` : ''}`);
        io.emit('dashboard_refresh');
        res.json({ message: 'Category deleted.', movedProducts: productCount, movedTo: productCount > 0 ? moveTo : null });
    } catch (error) {
        if (connection) {
            try { await connection.rollback(); } catch (_) { /* The transaction may already be closed. */ }
        }
        console.error('Failed to delete menu category:', error.message);
        res.status(500).json({ error: 'Failed to delete menu category.' });
    } finally {
        if (connection) connection.release();
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

app.put('/api/admin/branches/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const id = Number(req.params.id);
    const name = String(req.body?.name || '').trim();
    const code = String(req.body?.code || '').trim();
    const address = String(req.body?.address || '').trim();
    const phone = String(req.body?.phone || '').trim();
    if (!Number.isInteger(id) || id < 1 || !name || !code) {
        return res.status(400).json({ error: 'Enter a branch name and code.' });
    }

    try {
        const [existingBranches] = await pool.execute('SELECT id FROM branches WHERE id = ?', [id]);
        if (!existingBranches.length) return res.status(404).json({ error: 'Branch not found.' });
        await pool.execute(
            'UPDATE branches SET name = ?, code = ?, address = ?, phone = ? WHERE id = ?',
            [name, code, address, phone || null, id]
        );
        await logActivity(req.user.id, `Updated branch details: ${name} (ID: ${id})`);
        res.json({ message: 'Branch details updated.' });
    } catch (error) {
        console.error('Failed to update branch details:', error.message);
        res.status(500).json({ error: 'Failed to update branch details.' });
    }
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

app.post('/api/admin/riders', authenticateToken, verifyAdminOnly, async (req, res) => {
    const firstname = String(req.body?.firstname || '').trim();
    const lastname = String(req.body?.lastname || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = req.body?.password;
    if (!firstname || !lastname || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || typeof password !== 'string' || password.length < 8 || password.length > 128) {
        return res.status(400).json({ error: 'Enter a valid name, email, and password of at least 8 characters.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute('INSERT INTO users (firstname, lastname, email, password, role, phone, dob, branch) VALUES (?, ?, ?, ?, "rider", NULL, NULL, NULL)', [firstname, lastname, email, hashedPassword]);
        await logActivity(req.user.id, `Created new rider account: ${email}`);
        sendAccountCreatedEmail(email).catch(mailError => console.error('Rider account-created email failed:', mailError.message));
        return res.status(201).json({ message: 'Rider account created successfully.' });
    } catch (error) {
        console.error('Rider account creation failed:', error.message);
        return res.status(500).json({ error: 'Could not create the rider account. The email may already be in use.' });
    }
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
