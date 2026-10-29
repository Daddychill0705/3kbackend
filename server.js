const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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

// FIX: Process each column update individually so one existing column doesn't block the rest
const initializeDB = async () => {
    const columnsToAdd = [
        'ALTER TABLE users ADD COLUMN phone VARCHAR(50) DEFAULT NULL',
        'ALTER TABLE users ADD COLUMN dob DATE DEFAULT NULL',
        'ALTER TABLE users ADD COLUMN last_updated DATETIME DEFAULT NULL',
        'ALTER TABLE users ADD COLUMN branch VARCHAR(255) DEFAULT NULL'
    ];

    for (let query of columnsToAdd) {
        try {
            await pool.execute(query);
        } catch (e) {
            // Ignore error if this specific column already exists
        }
    }
};
initializeDB();

io.on('connection', (socket) => {
    socket.on('join_order', (orderId) => { socket.join(`order_${orderId}`); });
    socket.on('send_message', async (data) => {
        try {
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

app.get('/', (req, res) => res.send('3K Kitchen API is running successfully!'));

app.get('/api/admin/users', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [users] = await pool.execute('SELECT id, firstname, lastname, email, role, branch, created_at FROM users WHERE role IN ("admin", "cashier") ORDER BY role, firstname');
        res.json(users);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch users' }); }
});

app.post('/api/admin/users', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { firstname, lastname, email, password, role, branch } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (firstname, lastname, email, password, role, phone, dob, branch) VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)',
            [firstname, lastname, email, hashedPassword, role, branch || null]
        );
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) { 
        console.error("Admin User Create Error:", error);
        res.status(500).json({ error: 'Failed to create user. Email may already exist.' }); 
    }
});

app.delete('/api/admin/users/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
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

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
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
    } catch (error) { res.status(500).json({ error: 'Guest login failed.' }); }
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
    const { items, totalAmount, orderType, branch, address, phone, paymentMethod, notes, receipt_url } = req.body;
    const parsedItems = typeof items === 'string' ? JSON.parse(items) : items;
    if (!parsedItems || parsedItems.length === 0) return res.status(400).json({ error: 'Cart is empty' });

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const [orderResult] = await connection.execute(
            `INSERT INTO orders (user_id, total_amount, order_type, branch, delivery_address, contact_number, payment_method, gcash_receipt_url, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [req.user.id, totalAmount, orderType, branch, address || null, phone || null, paymentMethod, receipt_url || null, notes || null]
        );
        for (const item of parsedItems) {
            await connection.execute('INSERT INTO order_items (order_id, item_name, quantity, price) VALUES (?, ?, ?, ?)', [orderResult.insertId, item.name, item.qty, parseFloat(item.price)]);
        }
        await connection.commit();
        io.emit('dashboard_refresh'); 
        res.status(201).json({ message: 'Order placed', orderId: orderResult.insertId });
    } catch (error) {
        await connection.rollback();
        res.status(500).json({ error: 'Failed to place order' });
    } finally { connection.release(); }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        const [orders] = await pool.execute('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
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
        const [orders] = await pool.execute(`SELECT o.*, u.firstname, u.lastname, u.email FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC`);
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
        await pool.execute('UPDATE orders SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
        io.emit('dashboard_refresh'); 
        res.json({ message: 'Status updated' });
    } catch (error) { res.status(500).json({ error: 'Failed to update status' }); }
});

app.get('/api/menu', async (req, res) => {
    try {
        const [items] = await pool.execute('SELECT * FROM menu_items ORDER BY category, name');
        res.json(items);
    } catch (error) { res.status(500).json({ error: 'Failed to fetch menu' }); }
});

app.post('/api/admin/menu', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('INSERT INTO menu_items (name, category, price, image_url) VALUES (?, ?, ?, ?)', [req.body.name, req.body.category, req.body.price, req.body.image_url || '/img/default-food.jpg']);
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
        res.json({ message: 'Item updated' });
    } catch (error) { res.status(500).json({ error: 'Failed to update item' }); }
});

app.put('/api/admin/menu/:id/stock', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('UPDATE menu_items SET is_sold_out = ? WHERE id = ?', [req.body.is_sold_out, req.params.id]);
        res.json({ message: 'Stock updated' });
    } catch (error) { res.status(500).json({ error: 'Failed to update stock' }); }
});

app.delete('/api/admin/menu/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('DELETE FROM menu_items WHERE id = ?', [req.params.id]);
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
        res.status(201).json({ message: 'Branch added' });
    } catch (error) { res.status(500).json({ error: 'Failed to add branch' }); }
});

app.put('/api/admin/branches/:id/status', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('UPDATE branches SET is_active = ? WHERE id = ?', [req.body.is_active, req.params.id]);
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
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));