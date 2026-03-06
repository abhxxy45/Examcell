import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { 
  Users, 
  FileCheck, 
  CheckCircle, 
  AlertCircle,
  ArrowRight
} from 'lucide-react';
import { motion } from 'motion/react';

const StatCard = ({ icon: Icon, label, value, color }: { icon: any, label: string, value: string | number, color: string }) => (
  <div className="bg-white p-6 rounded-3xl shadow-sm border border-slate-200/60">
    <div className="flex items-center gap-5">
      <div className={`p-4 rounded-2xl ${color} text-white shadow-xl shadow-current/10`}>
        <Icon size={24} />
      </div>
      <div>
        <p className="text-xs font-bold text-slate-400 uppercase tracking-widest">{label}</p>
        <p className="text-3xl font-bold text-slate-900 mt-1">{value}</p>
      </div>
    </div>
  </div>
);

export const AdminDashboard = () => {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [stats, setStats] = useState({
    students: 0,
    forms: 0,
    approved: 0,
    pending: 0
  });

  useEffect(() => {
    const fetchStats = async () => {
      const [studentsRes, formsRes] = await Promise.all([
        fetch('/api/users/students', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/exam-forms', { headers: { Authorization: `Bearer ${token}` } })
      ]);
      const students = await studentsRes.json();
      const forms = await formsRes.json();
      
      setStats({
        students: students.length,
        forms: forms.length,
        approved: forms.filter((f: any) => f.status === 'approved').length,
        pending: forms.filter((f: any) => f.status === 'pending').length
      });
    };
    fetchStats();
  }, [token]);

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">Admin Dashboard</h1>
        <p className="text-slate-500">Overview of exam cell activities</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard icon={Users} label="Total Students" value={stats.students} color="bg-primary-600" />
        <StatCard icon={FileCheck} label="Exam Forms" value={stats.forms} color="bg-indigo-600" />
        <StatCard icon={CheckCircle} label="Approved" value={stats.approved} color="bg-emerald-600" />
        <StatCard icon={AlertCircle} label="Pending" value={stats.pending} color="bg-amber-600" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="bg-white p-8 rounded-[2rem] shadow-sm border border-slate-200/60">
          <h2 className="text-lg font-bold text-slate-900 mb-6 tracking-tight">Quick Actions</h2>
          <div className="grid grid-cols-2 gap-4">
            <button 
              onClick={() => navigate('/admin/students')}
              className="flex flex-col items-center justify-center p-8 rounded-2xl border-2 border-dashed border-slate-100 hover:border-primary-500 hover:bg-primary-50 transition-all group"
            >
              <div className="p-3 bg-slate-50 rounded-xl group-hover:bg-primary-100 transition-colors mb-3">
                <Users className="text-slate-400 group-hover:text-primary-600" size={20} />
              </div>
              <span className="text-xs font-bold text-slate-500 uppercase tracking-widest group-hover:text-primary-700">Add Student</span>
            </button>
            <button 
              onClick={() => navigate('/admin/exam-forms')}
              className="flex flex-col items-center justify-center p-8 rounded-2xl border-2 border-dashed border-slate-100 hover:border-primary-500 hover:bg-primary-50 transition-all group"
            >
              <div className="p-3 bg-slate-50 rounded-xl group-hover:bg-primary-100 transition-colors mb-3">
                <FileCheck className="text-slate-400 group-hover:text-primary-600" size={20} />
              </div>
              <span className="text-xs font-bold text-slate-500 uppercase tracking-widest group-hover:text-primary-700">Review Forms</span>
            </button>
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-bold text-slate-800">Recent Activity</h2>
            <button className="text-blue-600 text-sm font-semibold flex items-center gap-1">
              View All <ArrowRight size={14} />
            </button>
          </div>
          <div className="space-y-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center gap-4 p-3 rounded-xl bg-slate-50">
                <div className="w-10 h-10 rounded-full bg-blue-100 flex items-center justify-center text-blue-600 font-bold">
                  S
                </div>
                <div>
                  <p className="text-sm font-semibold text-slate-800">New Exam Form Submitted</p>
                  <p className="text-xs text-slate-500">Student ID: STU00{i} • 2 hours ago</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
