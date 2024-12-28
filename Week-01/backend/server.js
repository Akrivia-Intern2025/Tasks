const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// JWT secret key
const JWT_SECRET = "your-secure-jwt-secret"; // Replace with an environment variable in production

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MySQL Connection
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "task-01",
});

db.connect((err) => {
    if (err) {
        console.error("Error connecting to MySQL:", err);
        return;
    }
    console.log("Connected to MySQL database!");
});

// Create tables if not exists
db.query(
    `CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        firstname VARCHAR(50),
        lastname VARCHAR(50),
        email VARCHAR(100) UNIQUE,
        password VARCHAR(100)
    )`,
    (err) => {
        if (err) console.error("Error creating users table:", err);
    }
);

db.query(
    `CREATE TABLE IF NOT EXISTS tasks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        title VARCHAR(255),
        description TEXT,
        status ENUM('pending', 'completed') DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`,
    (err) => {
        if (err) console.error("Error creating tasks table:", err);
    }
);

// API to handle user registration
app.post("/register", (req, res) => {
    const { firstname, lastname, email, password } = req.body;

    if (!firstname || !lastname || !email || !password) {
        return res.status(400).json({ error: "All fields are required!" });
    }

    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            console.error("Error hashing password:", err);
            return res.status(500).json({ error: "Internal server error!" });
        }

        const sql = `INSERT INTO users (firstname, lastname, email, password) VALUES (?, ?, ?, ?)`;
        db.query(sql, [firstname, lastname, email, hashedPassword], (err) => {
            if (err) {
                console.error("Error inserting user:", err);
                if (err.code === "ER_DUP_ENTRY") {
                    return res.status(409).json({ error: "Email already exists!" });
                }
                return res.status(500).json({ error: "Database error!" });
            }
            res.status(201).json({ message: "User registered successfully!" });
        });
    });
});

// API to handle user login
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required!" });
    }

    const sql = `SELECT * FROM users WHERE email = ?`;
    db.query(sql, [email], (err, result) => {
        if (err) {
            console.error("Error during login:", err);
            return res.status(500).json({ error: "Database error!" });
        }

        if (result.length === 0) {
            return res.status(401).json({ error: "Invalid credentials!" });
        }

        bcrypt.compare(password, result[0].password, (err, isMatch) => {
            if (err) {
                console.error("Error comparing passwords:", err);
                return res.status(500).json({ error: "Internal server error!" });
            }

            if (!isMatch) {
                return res.status(401).json({ error: "Invalid credentials!" });
            }

            const token = jwt.sign({ id: result[0].id }, JWT_SECRET, { expiresIn: "1h" });
            res.status(200).json({ message: "Login successful!", token });
        });
    });
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"];
    if (!token) {
        return res.status(401).json({ error: "Access denied, token missing!" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: "Invalid or expired token!" });
        }
        req.user = decoded;
        next();
    });
};

// API to create a new task
app.post("/tasks", verifyToken, (req, res) => {
    const { title, description } = req.body;

    if (!title) {
        return res.status(400).json({ error: "Title is required!" });
    }

    const sql = `INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)`;
    db.query(sql, [req.user.id, title, description], (err) => {
        if (err) {
            console.error("Error creating task:", err);
            return res.status(500).json({ error: "Database error!" });
        }
        res.status(201).json({ message: "Task created successfully!" });
    });
});

// API to fetch tasks for authenticated user
app.get("/tasks", verifyToken, (req, res) => {
    const sql = `SELECT * FROM tasks WHERE user_id = ?`;
    db.query(sql, [req.user.id], (err, result) => {
        if (err) {
            console.error("Error fetching tasks:", err);
            return res.status(500).json({ error: "Database error!" });
        }
        res.status(200).json({ tasks: result });
    });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
