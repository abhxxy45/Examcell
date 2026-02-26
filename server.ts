import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database('exam_cell.db');
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-exam-cell-key';

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    studentId TEXT UNIQUE,
    name TEXT NOT NULL,
    course TEXT,
    year TEXT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin', 'student')) DEFAULT 'student'
  );

  CREATE TABLE IF NOT EXISTS exam_forms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    subjects TEXT NOT NULL,
    photoUrl TEXT,
    status TEXT CHECK(status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
    seatNumber TEXT,
    examCenter TEXT,
    FOREIGN KEY(userId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    marks TEXT NOT NULL, -- JSON string of subject: mark
    total INTEGER,
    percentage REAL,
    grade TEXT,
    FOREIGN KEY(userId) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS halls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    roomNumber TEXT NOT NULL,
    capacity INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS seating_allocations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hallId INTEGER NOT NULL,
    userId INTEGER NOT NULL,
    seatNumber TEXT NOT NULL,
    FOREIGN KEY(hallId) REFERENCES halls(id),
    FOREIGN KEY(userId) REFERENCES users(id)
  );
`);

// Seed Admin if not exists
const adminExists = db.prepare('SELECT * FROM users WHERE role = ?').get('admin');
if (!adminExists) {
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)').run(
    'System Admin',
    'admin@examcell.com',
    hashedPassword,
    'admin'
  );
}

const studentExists = db.prepare('SELECT * FROM users WHERE role = ?').get('student');
if (!studentExists) {
  const hashedPassword = bcrypt.hashSync('student123', 10);
  db.prepare('INSERT INTO users (studentId, name, course, year, email, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    'STU001',
    'John Student',
    'B.Tech IT',
    '4',
    'student@examcell.com',
    hashedPassword,
    'student'
  );
}

async function startServer() {
  const app = express();
  app.use(express.json());

  // Auth Middleware
  const authenticate = (req: any, res: any, next: any) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
      next();
    } catch (err) {
      res.status(401).json({ error: 'Invalid token' });
    }
  };

  const isAdmin = (req: any, res: any, next: any) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
  };

  // --- API Routes ---

  // Auth
  app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as any;
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, user: { id: user.id, name: user.name, role: user.role, email: user.email } });
  });

  app.post('/api/auth/register', (req, res) => {
    const { studentId, name, course, year, email, password } = req.body;
    
    // Basic validation
    if (!studentId || !name || !email || !password) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    try {
      db.prepare('INSERT INTO users (studentId, name, course, year, email, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        studentId, name, course, year, email, hashedPassword, 'student'
      );
      res.status(201).json({ message: 'Registration successful' });
    } catch (err: any) {
      if (err.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Email or Student ID already exists' });
      }
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // User Management (Admin)
  app.get('/api/users/students', authenticate, isAdmin, (req, res) => {
    const students = db.prepare('SELECT id, studentId, name, course, year, email FROM users WHERE role = ?').all('student');
    res.json(students);
  });

  app.post('/api/users/students', authenticate, isAdmin, (req, res) => {
    const { studentId, name, course, year, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    try {
      db.prepare('INSERT INTO users (studentId, name, course, year, email, password, role) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
        studentId, name, course, year, email, hashedPassword, 'student'
      );
      res.status(201).json({ message: 'Student created' });
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  });

  app.put('/api/users/students/:id', authenticate, isAdmin, (req, res) => {
    const { studentId, name, course, year, email } = req.body;
    db.prepare('UPDATE users SET studentId = ?, name = ?, course = ?, year = ?, email = ? WHERE id = ?').run(
      studentId, name, course, year, email, req.params.id
    );
    res.json({ message: 'Student updated' });
  });

  app.delete('/api/users/students/:id', authenticate, isAdmin, (req, res) => {
    db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
    res.json({ message: 'Student deleted' });
  });

  // Exam Forms
  app.post('/api/exam-forms', authenticate, (req: any, res) => {
    const { subjects, photoUrl } = req.body;
    const existing = db.prepare('SELECT * FROM exam_forms WHERE userId = ?').get(req.user.id);
    if (existing) return res.status(400).json({ error: 'Form already submitted' });
    
    db.prepare('INSERT INTO exam_forms (userId, subjects, photoUrl) VALUES (?, ?, ?)').run(
      req.user.id, JSON.stringify(subjects), photoUrl
    );
    res.status(201).json({ message: 'Form submitted' });
  });

  app.get('/api/exam-forms/my', authenticate, (req: any, res) => {
    const form = db.prepare(`
      SELECT ef.*, u.name, u.studentId, u.course, u.year 
      FROM exam_forms ef 
      JOIN users u ON ef.userId = u.id 
      WHERE ef.userId = ?
    `).get(req.user.id);
    res.json(form || null);
  });

  app.get('/api/exam-forms', authenticate, isAdmin, (req, res) => {
    const forms = db.prepare(`
      SELECT ef.*, u.name, u.studentId, u.course, u.year 
      FROM exam_forms ef 
      JOIN users u ON ef.userId = u.id
    `).all();
    res.json(forms);
  });

  app.patch('/api/exam-forms/:id', authenticate, isAdmin, (req, res) => {
    const { status, seatNumber, examCenter } = req.body;
    db.prepare('UPDATE exam_forms SET status = ?, seatNumber = ?, examCenter = ? WHERE id = ?').run(
      status, seatNumber, examCenter, req.params.id
    );
    res.json({ message: 'Form updated' });
  });

  // Results
  app.post('/api/results', authenticate, isAdmin, (req, res) => {
    const { userId, marks } = req.body;
    const marksObj = marks; // Expecting { "Math": 80, "Physics": 75 }
    const total = Object.values(marksObj).reduce((a: any, b: any) => a + b, 0) as number;
    const count = Object.keys(marksObj).length;
    const percentage = (total / (count * 100)) * 100;
    
    let grade = 'F';
    if (percentage >= 90) grade = 'A+';
    else if (percentage >= 80) grade = 'A';
    else if (percentage >= 70) grade = 'B';
    else if (percentage >= 60) grade = 'C';
    else if (percentage >= 50) grade = 'D';

    db.prepare('INSERT INTO results (userId, marks, total, percentage, grade) VALUES (?, ?, ?, ?, ?)').run(
      userId, JSON.stringify(marksObj), total, percentage, grade
    );
    res.status(201).json({ message: 'Result processed' });
  });

  app.get('/api/results/my', authenticate, (req: any, res) => {
    const result = db.prepare(`
      SELECT r.*, u.name, u.studentId, u.course, u.year 
      FROM results r 
      JOIN users u ON r.userId = u.id 
      WHERE r.userId = ?
    `).get(req.user.id);
    res.json(result || null);
  });

  // Halls & Allocation
  app.post('/api/halls', authenticate, isAdmin, (req, res) => {
    const { roomNumber, capacity } = req.body;
    db.prepare('INSERT INTO halls (roomNumber, capacity) VALUES (?, ?)').run(roomNumber, capacity);
    res.status(201).json({ message: 'Hall added' });
  });

  app.get('/api/halls', authenticate, isAdmin, (req, res) => {
    const halls = db.prepare('SELECT * FROM halls').all();
    res.json(halls);
  });

  app.post('/api/allocate-seats', authenticate, isAdmin, (req, res) => {
    // Simple allocation logic
    const students = db.prepare(`
      SELECT u.id, u.name, u.studentId 
      FROM users u 
      JOIN exam_forms ef ON u.id = ef.userId 
      WHERE ef.status = 'approved' 
      AND u.id NOT IN (SELECT userId FROM seating_allocations)
    `).all() as any[];

    const halls = db.prepare('SELECT * FROM halls').all() as any[];
    
    let studentIdx = 0;
    db.transaction(() => {
      for (const hall of halls) {
        for (let i = 1; i <= hall.capacity; i++) {
          if (studentIdx >= students.length) break;
          const student = students[studentIdx++];
          db.prepare('INSERT INTO seating_allocations (hallId, userId, seatNumber) VALUES (?, ?, ?)').run(
            hall.id, student.id, `${hall.roomNumber}-${i}`
          );
        }
        if (studentIdx >= students.length) break;
      }
    })();

    res.json({ message: `Allocated ${studentIdx} students` });
  });

  app.get('/api/seating-arrangement', authenticate, (req, res) => {
    const arrangement = db.prepare(`
      SELECT sa.*, h.roomNumber, u.name, u.studentId, u.course
      FROM seating_allocations sa
      JOIN halls h ON sa.hallId = h.id
      JOIN users u ON sa.userId = u.id
    `).all();
    res.json(arrangement);
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, 'dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
