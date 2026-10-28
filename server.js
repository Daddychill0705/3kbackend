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

// Enable CORS for localhost and your Vercel domains
const allowedOrigins = [
    'http://localhost:5173',
    'https://3kitchen.vercel.app',
    'https://3kfrontend.vercel.app',
    process.env.FRONTEND_URL
];

app.use(cors({
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const server = http.createServer(app);
const io = new Server(server, {
    cors: { 
        origin: allowedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true
    }
});

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

const pool = mysql.createPool(process.env.TIDB_URI);

io.on('connection', (socket) => {
    socket.on('join_order', (orderId) => {
        socket.join(`order_${orderId}`);
    });
    
    socket.on('send_message', async (data) => {
        try {
            await pool.execute(
                'INSERT INTO order_chats (order_id, sender, message) VALUES (?, ?, ?)',
                [data.orderId, data.sender, data.text]
            );
            io.to(`order_${data.orderId}`).emit('receive_message', data);
        } catch (error) {
            console.error('Socket DB Insert Error:', error);
        }
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

// Root Health Check to fix "Cannot GET /"
app.get('/', (req, res) => {
    res.send('3K Kitchen API is running successfully!');
});

app.get('/api/admin/users', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [users] = await pool.execute('SELECT id, firstname, lastname, email, role, created_at FROM users WHERE role IN ("admin", "cashier") ORDER BY role, firstname');
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/api/admin/users', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { firstname, lastname, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (firstname, lastname, email, password, role) VALUES (?, ?, ?, ?, ?)',
            [firstname, lastname, email, hashedPassword, role]
        );
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create user. Email may already exist.' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('DELETE FROM users WHERE id = ?', [req.params.id]);
        res.json({ message: 'User deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.post('/api/register', async (req, res) => {
    const { firstname, lastname, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.execute(
            'INSERT INTO users (firstname, lastname, email, password, role) VALUES (?, ?, ?, ?, ?)',
            [firstname, lastname, email, hashedPassword, role || 'customer']
        );
        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed or email exists.' });
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
        
        // Return extra fields so the frontend has them in context
        res.json({ 
            token, 
            user: { 
                id: user.id, 
                name: `${user.firstname} ${user.lastname}`, 
                email: user.email, 
                role: user.role,
                phone: user.phone || '',
                dob: user.dob || '',
                last_updated: user.last_updated || null
            } 
        });
    } catch (error) {
        res.status(500).json({ error: 'Login failed.' });
    }
});

app.post('/api/guest', async (req, res) => {
    try {
        let [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', ['guest@3kkitchen.local']);
        let user;
        if (rows.length === 0) {
            const hashedPassword = await bcrypt.hash('guest123', 10);
            const [result] = await pool.execute(
                'INSERT INTO users (firstname, lastname, email, password, role) VALUES (?, ?, ?, ?, ?)',
                ['Guest', 'User', 'guest@3kkitchen.local', hashedPassword, 'customer']
            );
            user = { id: result.insertId, role: 'customer', firstname: 'Guest', lastname: 'User', email: 'guest@3kkitchen.local' };
        } else {
            user = rows[0];
        }
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: { id: user.id, name: `${user.firstname} ${user.lastname}`, email: user.email, role: user.role, phone: '', dob: '', last_updated: null } });
    } catch (error) {
        res.status(500).json({ error: 'Guest login failed.' });
    }
});

// --- NEW ROUTE: UPDATE PROFILE WITH COOLDOWN ---
app.put('/api/users/profile', authenticateToken, async (req, res) => {
    const { email, phone, dob } = req.body;
    const userId = req.user.id;

    try {
        // First ensure these columns exist (for seamless deployment)
        try {
            await pool.execute('ALTER TABLE users ADD COLUMN phone VARCHAR(50) DEFAULT NULL');
            await pool.execute('ALTER TABLE users ADD COLUMN dob DATE DEFAULT NULL');
            await pool.execute('ALTER TABLE users ADD COLUMN last_updated DATETIME DEFAULT NULL');
        } catch (e) {
            // Ignore if columns already exist
        }

        // Check the current cooldown
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

        // Perform the update
        await pool.execute(
            'UPDATE users SET email = ?, phone = ?, dob = ?, last_updated = NOW() WHERE id = ?',
            [email, phone, dob || null, userId]
        );

        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error("Profile Update Error:", error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.post('/api/orders', authenticateToken, async (req, res) => {
    const { items, totalAmount, orderType, branch, address, phone, paymentMethod, notes, receipt_url } = req.body;
    const userId = req.user.id;
    
    const parsedItems = typeof items === 'string' ? JSON.parse(items) : items;

    if (!parsedItems || parsedItems.length === 0) return res.status(400).json({ error: 'Cart is empty' });

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const [orderResult] = await connection.execute(
            `INSERT INTO orders (user_id, total_amount, order_type, branch, delivery_address, contact_number, payment_method, gcash_receipt_url, notes) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [userId, totalAmount, orderType, branch, address || null, phone || null, paymentMethod, receipt_url || null, notes || null]
        );
        const orderId = orderResult.insertId;

        for (const item of parsedItems) {
            await connection.execute(
                'INSERT INTO order_items (order_id, item_name, quantity, price) VALUES (?, ?, ?, ?)',
                [orderId, item.name, item.qty, parseFloat(item.price)]
            );
        }
        await connection.commit();
        io.emit('dashboard_refresh'); 
        res.status(201).json({ message: 'Order placed successfully', orderId });
    } catch (error) {
        await connection.rollback();
        console.error("Order Creation Error:", error);
        res.status(500).json({ error: 'Failed to place order' });
    } finally {
        connection.release();
    }
});

app.get('/api/admin/orders', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [orders] = await pool.execute(`
            SELECT o.*, u.firstname, u.lastname, u.email 
            FROM orders o JOIN users u ON o.user_id = u.id ORDER BY o.created_at DESC
        `);
        for (let order of orders) {
            const [items] = await pool.execute("SELECT item_name as name, quantity as qty, price FROM order_items WHERE order_id = ?", [order.id]);
            order.itemsData = items;
            order.items = items.map(i => `${i.qty}x ${i.name}`).join(', ');
            order.date = new Date(order.created_at).toLocaleString();
            order.customerName = `${order.firstname} ${order.lastname}`;
        }
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch admin orders' });
    }
});

app.put('/api/admin/orders/:id/status', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { status } = req.body;
    try {
        await pool.execute('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
        io.emit('dashboard_refresh'); 
        res.json({ message: 'Order status updated' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update status' });
    }
});

app.get('/api/menu', async (req, res) => {
    try {
        const [items] = await pool.execute('SELECT * FROM menu_items ORDER BY category, name');
        res.json(items);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch menu' });
    }
});

app.post('/api/admin/menu', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { name, category, price, image_url } = req.body;
    const finalImageUrl = image_url || '/img/default-food.jpg';
    
    try {
        await pool.execute(
            'INSERT INTO menu_items (name, category, price, image_url) VALUES (?, ?, ?, ?)',
            [name, category, price, finalImageUrl]
        );
        res.status(201).json({ message: 'Item added successfully' });
    } catch (error) {
        console.error("Menu Add Error:", error);
        res.status(500).json({ error: 'Failed to add item' });
    }
});

app.put('/api/admin/menu/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { name, category, price, image_url } = req.body;
    try {
        if (image_url) {
            // Update everything including the new image
            await pool.execute(
                'UPDATE menu_items SET name = ?, category = ?, price = ?, image_url = ? WHERE id = ?',
                [name, category, price, image_url, req.params.id]
            );
        } else {
            // Keep the old image, update just the text
            await pool.execute(
                'UPDATE menu_items SET name = ?, category = ?, price = ? WHERE id = ?',
                [name, category, price, req.params.id]
            );
        }
        res.json({ message: 'Item updated successfully' });
    } catch (error) {
        console.error("Menu Update Error:", error);
        res.status(500).json({ error: 'Failed to update item' });
    }
});

app.put('/api/admin/menu/:id/stock', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { is_sold_out } = req.body;
    try {
        await pool.execute('UPDATE menu_items SET is_sold_out = ? WHERE id = ?', [is_sold_out, req.params.id]);
        res.json({ message: 'Stock status updated' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update stock' });
    }
});

app.delete('/api/admin/menu/:id', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        await pool.execute('DELETE FROM menu_items WHERE id = ?', [req.params.id]);
        res.json({ message: 'Item deleted' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete item' });
    }
});

app.get('/api/branches', async (req, res) => {
    try {
        const [branches] = await pool.execute('SELECT * FROM branches ORDER BY name');
        res.json(branches);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch branches' });
    }
});

app.post('/api/admin/branches', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { name, code, address, phone } = req.body;
    try {
        await pool.execute('INSERT INTO branches (name, code, address, phone) VALUES (?, ?, ?, ?)', [name, code, address, phone]);
        res.status(201).json({ message: 'Branch added' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add branch' });
    }
});

app.put('/api/admin/branches/:id/status', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    const { is_active } = req.body;
    try {
        await pool.execute('UPDATE branches SET is_active = ? WHERE id = ?', [is_active, req.params.id]);
        res.json({ message: 'Branch status updated' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update branch' });
    }
});

app.get('/api/admin/riders', authenticateToken, verifyAdminOrStaff, async (req, res) => {
    try {
        const [riders] = await pool.execute('SELECT id, firstname, lastname, email, created_at FROM users WHERE role = "rider"');
        res.json(riders);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch riders' });
    }
});

app.get('/api/orders/:id/chat', authenticateToken, async (req, res) => {
    try {
        await pool.execute(`
            CREATE TABLE IF NOT EXISTS order_chats (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                sender VARCHAR(255) NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
            )
        `);

        const [messages] = await pool.execute(
            'SELECT sender, message as text, DATE_FORMAT(created_at, "%h:%i %p") as time FROM order_chats WHERE order_id = ? ORDER BY created_at ASC',
            [req.params.id]
        );
        res.json(messages);
    } catch (error) {
        console.error("Chat fetch error:", error);
        res.status(500).json({ error: 'Failed to fetch chat history' });
    }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));