import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './AuthContext';
import { Layout } from './components/Layout';
import { Login } from './pages/Login';
import { AdminDashboard } from './pages/AdminDashboard';
import { StudentManagement } from './pages/StudentManagement';
import { ExamFormReview } from './pages/ExamFormReview';
import { ResultProcessing } from './pages/ResultProcessing';
import { HallAllocation } from './pages/HallAllocation';
import { StudentDashboard } from './pages/StudentDashboard';
import { ExamFormSubmission } from './pages/ExamFormSubmission';
import { HallTicketView } from './pages/HallTicketView';
import { StudentResults } from './pages/StudentResults';
import { FeesPayment } from './pages/FeesPayment';

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/login" replace />} />
            
            {/* Admin Routes */}
            <Route path="admin" element={<AdminDashboard />} />
            <Route path="admin/students" element={<StudentManagement />} />
            <Route path="admin/exam-forms" element={<ExamFormReview />} />
            <Route path="admin/results" element={<ResultProcessing />} />
            <Route path="admin/halls" element={<HallAllocation />} />
            
            {/* Student Routes */}
            <Route path="student" element={<StudentDashboard />} />
            <Route path="student/exam-form" element={<ExamFormSubmission />} />
            <Route path="student/fees" element={<FeesPayment />} />
            <Route path="student/hall-ticket" element={<HallTicketView />} />
            <Route path="student/results" element={<StudentResults />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
