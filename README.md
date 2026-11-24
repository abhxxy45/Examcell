# ExamCell — Exam Management System

Web-based examination management platform for managing exams, student records, and results digitally.

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React 19, TypeScript, Vite |
| **Backend** | Node.js, Express.js, TypeScript |
| **Database** | MySQL |
| **API** | REST |
| **Build** | Vite, npm |

## Project Structure

```
Examcell/
├── src/                    # Frontend source
│   ├── components/         # React components
│   ├── services/           # API services
│   ├── types/              # TypeScript types
│   └── ...
├── server.ts               # Express server entry
├── vite.config.ts          # Vite configuration
├── tsconfig.json           # TypeScript config
├── package.json            # Dependencies
└── README.md
```

## Features

- **Exam Management**: Create, schedule, and manage examinations
- **Student Records**: Digital student database with profiles
- **Results Management**: Enter, calculate, and publish results
- **Role-based Access**: Admin, faculty, and student dashboards
- **REST API**: Structured backend endpoints for all operations

## Setup Instructions

### Prerequisites
- Node.js 18+
- MySQL 8.0+
- npm

### Installation

```bash
# Clone repository
git clone https://github.com/abhxxy45/Examcell.git
cd Examcell

# Install dependencies
npm install

# Configure database
# Update database credentials in server.ts or config file

# Run database migrations (if applicable)
# mysql -u root -p < database/schema.sql

# Start development server
npm run dev
```

### Environment Variables

Create `.env` file (see `.env.example` if available):

```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=examcell
PORT=3000
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/exams | List all exams |
| POST | /api/exams | Create new exam |
| GET | /api/students | List all students |
| POST | /api/students | Add new student |
| GET | /api/results | Get results |
| POST | /api/results | Submit results |

## Development

```bash
# Frontend dev server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Screenshots

*To be added*

## License

MIT License — see [LICENSE](LICENSE) for details.

---

**Repository**: https://github.com/abhxxy45/Examcell