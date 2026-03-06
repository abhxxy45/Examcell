import React, { useEffect, useState } from 'react';
import { useAuth } from '../AuthContext';
import { ExamForm, Result } from '../types';
import { 
  FileText, 
  CheckCircle, 
  Clock, 
  AlertCircle,
  GraduationCap,
  Calendar,
  CreditCard
} from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '../lib/utils';
import { Link } from 'react-router-dom';

export const StudentDashboard = () => {
  const { token, user } = useAuth();
  const [form, setForm] = useState<ExamForm | null>(null);
  const [result, setResult] = useState<Result | null>(null);
  const [userProfile, setUserProfile] = useState<any>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [formRes, resultRes, userRes] = await Promise.all([
          fetch('/api/exam-forms/my', { headers: { Authorization: `Bearer ${token}` } }),
          fetch('/api/results/my', { headers: { Authorization: `Bearer ${token}` } }),
          fetch('/api/users/me', { headers: { Authorization: `Bearer ${token}` } })
        ]);
        
        if (formRes.ok) {
          const text = await formRes.text();
          if (text) setForm(JSON.parse(text));
        }
        
        if (resultRes.ok) {
          const text = await resultRes.text();
          if (text) setResult(JSON.parse(text));
        }

        if (userRes.ok) {
          const data = await userRes.json();
          setUserProfile(data);
        }
      } catch (err) {
        console.error('Failed to fetch dashboard data:', err);
      }
    };
    fetchData();
  }, [token]);

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Welcome, {userProfile?.name || user?.name}</h1>
          <p className="text-slate-500">
            Student ID: {userProfile?.studentId || '...'} • {userProfile?.course || '...'}
          </p>
        </div>
        <div className="hidden md:block text-right">
          <p className="text-sm font-semibold text-slate-700">{new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric' })}</p>
          <p className="text-xs text-slate-400">Academic Session 2025-26</p>
        </div>
      </div>

      {userProfile?.feeStatus === 'unpaid' && (
        <motion.div 
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-red-50 border border-red-100 p-6 rounded-3xl flex flex-col md:flex-row items-center justify-between gap-4 shadow-xl shadow-red-100/50"
        >
          <div className="flex items-center gap-4">
            <div className="p-3 bg-red-100 text-red-600 rounded-2xl">
              <AlertCircle size={24} />
            </div>
            <div>
              <h3 className="font-bold text-red-900">Fees Payment Pending</h3>
              <p className="text-sm text-red-700">Please pay your academic fees to enable exam form submission.</p>
            </div>
          </div>
          <Link 
            to="/student/fees" 
            className="bg-red-600 hover:bg-red-700 text-white px-6 py-2.5 rounded-xl font-bold text-sm transition-all active:scale-95 flex items-center gap-2"
          >
            <CreditCard size={18} />
            Pay Now
          </Link>
        </motion.div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-8 rounded-3xl shadow-sm border border-slate-200/60">
          <div className="flex items-center gap-4 mb-6">
            <div className="p-3 bg-primary-50 text-primary-600 rounded-2xl">
              <FileText size={24} />
            </div>
            <h3 className="font-bold text-slate-900 tracking-tight">Exam Form</h3>
          </div>
          {form ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">Status</span>
                <span className={cn(
                  "px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest",
                  form.status === 'approved' ? "bg-emerald-100 text-emerald-700" :
                  form.status === 'rejected' ? "bg-red-100 text-red-700" :
                  "bg-amber-100 text-amber-700"
                )}>
                  {form.status}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-medium">Submitted: {new Date().toLocaleDateString()}</p>
            </div>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-slate-400 italic">No active submission</p>
              <button className="text-primary-600 text-sm font-bold hover:text-primary-700 transition-colors">Fill Form Now →</button>
            </div>
          )}
        </div>

        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100">
          <div className="flex items-center gap-4 mb-4">
            <div className="p-3 bg-indigo-50 text-indigo-600 rounded-xl">
              <Calendar size={24} />
            </div>
            <h3 className="font-bold text-slate-800">Hall Ticket</h3>
          </div>
          {form?.status === 'approved' ? (
            <div className="space-y-3">
              <p className="text-sm text-slate-600">Seat: <span className="font-bold">{form.seatNumber}</span></p>
              <p className="text-xs text-slate-400">Center: {form.examCenter}</p>
              <div className="flex gap-4">
                <Link to="/student/hall-ticket" className="text-indigo-600 text-xs font-bold hover:underline">View</Link>
                <Link to="/student/hall-ticket" className="text-slate-500 text-xs font-bold hover:underline">Download</Link>
              </div>
            </div>
          ) : (
            <p className="text-sm text-slate-500 italic">Available after form approval</p>
          )}
        </div>

        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100">
          <div className="flex items-center gap-4 mb-4">
            <div className="p-3 bg-emerald-50 text-emerald-600 rounded-xl">
              <GraduationCap size={24} />
            </div>
            <h3 className="font-bold text-slate-800">Latest Result</h3>
          </div>
          {result ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-500">Grade</span>
                <span className="text-xl font-bold text-emerald-600">{result.grade}</span>
              </div>
              <p className="text-xs text-slate-400">Percentage: {result.percentage.toFixed(2)}%</p>
              <div className="flex gap-4 pt-2">
                <Link to="/student/results" className="text-emerald-600 text-xs font-bold hover:underline">View</Link>
                <Link to="/student/results" className="text-slate-500 text-xs font-bold hover:underline">Download</Link>
              </div>
            </div>
          ) : (
            <p className="text-sm text-slate-500 italic">No results published yet</p>
          )}
        </div>
      </div>

      <div className="bg-white p-8 rounded-2xl border border-slate-100">
        <h2 className="text-lg font-bold text-slate-800 mb-6">Upcoming Examinations</h2>
        <div className="space-y-4">
          {[
            { subject: 'Mathematics IV', date: 'May 15, 2025', time: '10:00 AM' },
            { subject: 'Data Structures', date: 'May 18, 2025', time: '10:00 AM' },
            { subject: 'Operating Systems', date: 'May 21, 2025', time: '10:00 AM' }
          ].map((exam, i) => (
            <div key={i} className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 bg-white rounded-lg flex flex-col items-center justify-center border border-slate-200">
                  <span className="text-[10px] font-bold text-slate-400 uppercase">{exam.date.split(' ')[0]}</span>
                  <span className="text-lg font-bold text-blue-600 leading-none">{exam.date.split(' ')[1].replace(',', '')}</span>
                </div>
                <div>
                  <p className="font-bold text-slate-800">{exam.subject}</p>
                  <p className="text-xs text-slate-500">{exam.time}</p>
                </div>
              </div>
              <span className="text-xs font-semibold text-slate-400">Theory Exam</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
