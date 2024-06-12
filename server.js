

const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(bodyParser.json());

// MySQL connection for main database
const db = mysql.createConnection({
    host: 'your_host',
    user: 'user_name',
    password: 'your_password',
    database: 'database_name',
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});
const generateToken = (user) => {
    return jwt.sign({ id: user.id, username: user.username }, 'your_jwt_secret', { expiresIn: '1h' });
};




app.post('/register', async (req, res) => {
    const { username, userLastName, userEmail, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO registered_users (username, userLastName, userEmail, password) VALUES (?, ?, ?, ?)';
    db.query(query, [username, userLastName, userEmail, hashedPassword], (err, result) => {
        if (err) {
            console.error('Error registering user:', err);
            return res.status(500).json({ error: 'User registration failed' });
        }
        const user = { id: result.insertId, username, userLastName, userEmail };
        const token = generateToken(user);
        res.status(201).json({ token, username: user.username });
    });
});




app.post('/login', async (req, res) => {
    const { userEmail, password } = req.body;

    const query = 'SELECT * FROM registered_users WHERE userEmail = ?';
    db.query(query, [userEmail], async (err, results) => {
        if (err || results.length === 0) {
            console.error('Error finding user:', err);
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = results[0];
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const token = generateToken(user);
        res.json({ token, username: user.username });
    });
});

// Middleware for verifying token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ error: 'No token provided' });
    }

    jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to authenticate token' });
        }
        req.userId = decoded.id;
        next();
    });
};

// Protected route
app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'This is a protected route' });
});

// Get all users (for demonstration purposes)
app.get('/users', (req, res) => {
    db.query('SELECT * FROM users', (err, results) => {
        if (err) {
            console.error('Error fetching data from MySQL database:', err);
            res.status(500).send('Error fetching data');
            return;
        }
        res.json(results);
    });
});

// Add a new user (for demonstration purposes)
app.post('/users', (req, res) => {
    const user = req.body;
    // console.log('Received user data:', user);

    // Check for undefined or null values and replace them with empty strings
    const values = [
        user.AssociatedClient ?? '',
        user.AssociatedContract ?? '',
        user.Lawyer ?? '',
        user.BeneficiaryName ?? '',
        user.Founders ?? '',
        user.Director ?? '',
        user.PartiesOfDispute ?? '',
        user.AssociatedCompanies ?? '',
        user.AssociatedCases ?? '',
        user.createdBy ?? '',
    ];

    // console.log('Values to be inserted:', values);

    const query = `
        INSERT INTO users 
        (AssociatedClient, AssociatedContract, Lawyer, BeneficiaryName, Founders, Director, PartiesOfDispute, AssociatedCompanies, AssociatedCases, createdBy) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(query, values, (err, result) => {
        if (err) {
            console.error('Error inserting data into MySQL database:', err);
            res.status(500).send('Error inserting data');
            return;
        }
        res.status(201).json({ id: result.insertId, message: 'User added successfully' });
    });
});

// PUT запрос для обновления данных пользователя
app.put('/users/:userId', (req, res) => {
    const userId = req.params.userId;
    const updatedData = req.body;

    // Удаляем поле Id из объекта обновленных данных
    delete updatedData.Id;

    const query = `
      UPDATE users 
      SET ? 
      WHERE Id = ?
  `;

    db.query(query, [updatedData, userId], (err, result) => {
        if (err) {
            console.error('Error updating user data in MySQL database:', err);
            res.status(500).send('Error updating user data');
            return;
        }
        res.status(200).send('User data updated successfully');
    });
});

// DELETE запрос для удаления данных пользователя
app.delete('/users/:userId', (req, res) => {
    const userId = req.params.userId;

    const query = `
        DELETE FROM users 
        WHERE Id = ?
    `;

    db.query(query, [userId], (err, result) => {
        if (err) {
            console.error('Error deleting user data from MySQL database:', err);
            res.status(500).send('Error deleting user data');
            return;
        }
        res.status(200).send('User data deleted successfully');
    });
});


app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
