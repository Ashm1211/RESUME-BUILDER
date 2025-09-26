const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
const port = 3001; // You can use any port, but this is a common choice.

// Middleware
app.use(cors());
app.use(express.json());

// MySQL Connection
// MySQL Connection (Promise based)
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '12345678', // put your MySQL root password here
  database: 'resume_builder'
}).promise();


// Helper function for user authentication
const authenticateUser = async (req, res, next) => {
    const { userId } = req.headers; // Assuming userId is sent in the header

    if (!userId) {
        return res.status(401).json({ message: 'Authentication required' });
    }

    // Check if the user exists
    const [rows] = await db.execute('SELECT user_id FROM users WHERE user_id = ?', [userId]);

    if (rows.length === 0) {
        return res.status(404).json({ message: 'User not found' });
    }
    
    // Attach user_id to the request object for use in other routes
    req.userId = userId;
    next();
};

// --- API Endpoints ---

// 1. User Registration [cite: 58]
app.post('/api/register', async (req, res) => {
  const { full_name, email, password } = req.body;

  if (!full_name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    // Hash the password 
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.execute(
      'INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)',
      [full_name, email, hashedPassword]
    );

    res.status(201).json({ message: 'User registered successfully', userId: result.insertId });
  } catch (error) {
    console.error(error);
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Email already exists' });
    }
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// 2. User Login [cite: 58]
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.execute('SELECT user_id, password FROM users WHERE email = ?', [email]);

    if (rows.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    res.status(200).json({ message: 'Login successful', userId: user.user_id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// 3. Save Resume Data
app.post('/api/resume/save', authenticateUser, async (req, res) => {
    const { title, content } = req.body;
    const userId = req.userId;

    if (!title || !content) {
        return res.status(400).json({ message: 'Title and content are required' });
    }

    try {
        const [result] = await db.execute(
            'INSERT INTO resumes (user_id, title, content) VALUES (?, ?, ?)',
            [userId, title, JSON.stringify(content)]
        );
        res.status(201).json({ message: 'Resume saved successfully', resumeId: result.insertId });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error while saving resume' });
    }
});

// 4. Get All Resumes for a User
app.get('/api/resumes', authenticateUser, async (req, res) => {
    const userId = req.userId;

    try {
        const [rows] = await db.execute('SELECT resume_id, title, created_at FROM resumes WHERE user_id = ?', [userId]);
        res.status(200).json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error while fetching resumes' });
    }
});

// 5. Get a Specific Resume by ID
app.get('/api/resume/:id', authenticateUser, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;

    try {
        const [rows] = await db.execute('SELECT content FROM resumes WHERE resume_id = ? AND user_id = ?', [id, userId]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Resume not found' });
        }

        res.status(200).json(rows[0].content);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error while fetching resume' });
    }
});

// Start the server
app.listen(port, () => {
  console.log(`Backend server listening at http://localhost:${port}`);
});