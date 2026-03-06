import React, { useEffect, useState } from 'react';
import { useAuth } from '../AuthContext';
import { ExamForm } from '../types';
import { Check, X, Eye, MapPin, Hash } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '../lib/utils';

export const ExamFormReview = () => {
  const { token } = useAuth();
  const [forms, setForms] = useState<ExamForm[]>([]);
  const [selectedForm, setSelectedForm] = useState<ExamForm | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [approvalData, setApprovalData] = useState({
    seatNumber: '',
    examCenter: 'Main Campus Hall A'
  });

  const fetchForms = async () => {
    const res = await fetch('/api/exam-forms', {
      headers: { Authorization: `Bearer ${token}` }
    });
    const data = await res.json();
    setForms(data);
  };

  useEffect(() => {
    fetchForms();
  }, [token]);

  const handleStatusUpdate = async (id: number, status: 'approved' | 'rejected') => {
    const res = await fetch(`/api/exam-forms/${id}`, {
      method: 'PATCH',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ 
        status, 
        ...(status === 'approved' ? approvalData : {})
      })
    });

    if (res.ok) {
      setIsModalOpen(false);
      setSelectedForm(null);
      fetchForms();
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">Exam Form Review</h1>
        <p className="text-slate-500">Approve or reject student exam applications</p>
      </div>

      <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider">
                <th className="px-6 py-4 font-semibold">Student</th>
                <th className="px-6 py-4 font-semibold">Course</th>
                <th className="px-6 py-4 font-semibold">Subjects</th>
                <th className="px-6 py-4 font-semibold">Status</th>
                <th className="px-6 py-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {forms.map((form) => (
                <tr key={form.id} className="hover:bg-slate-50 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center text-primary-600 font-bold text-xs">
                        {form.name?.charAt(0)}
                      </div>
                      <div>
                        <p className="font-semibold text-slate-700">{form.name}</p>
                        <p className="text-xs text-slate-400">{form.studentId}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-600">{form.course}</td>
                  <td className="px-6 py-4">
                    <div className="flex flex-wrap gap-1">
                      {JSON.parse(form.subjects).map((s: string) => (
                        <span key={s} className="px-2 py-0.5 bg-slate-100 text-slate-600 rounded text-[10px] font-medium">
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className={cn(
                      "px-2 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider",
                      form.status === 'approved' ? "bg-emerald-100 text-emerald-700" :
                      form.status === 'rejected' ? "bg-red-100 text-red-700" :
                      "bg-amber-100 text-amber-700"
                    )}>
                      {form.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => {
                            setSelectedForm(form);
                            setIsModalOpen(true);
                          }}
                          className="p-2 text-slate-400 hover:text-primary-600 hover:bg-primary-50 rounded-lg transition-colors"
                        >
                          <Eye size={18} />
                        </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <AnimatePresence>
        {isModalOpen && selectedForm && (
          <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsModalOpen(false)}
              className="absolute inset-0 bg-slate-900/40 backdrop-blur-sm"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 20 }}
              className="relative w-full max-w-lg bg-white rounded-2xl shadow-2xl p-6"
            >
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-bold text-slate-800">Review Exam Form</h2>
                <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-slate-600">
                  <X size={24} />
                </button>
              </div>

              <div className="space-y-6">
                <div className="flex items-center gap-4 p-4 bg-slate-50 rounded-xl">
                  <div className="w-12 h-12 bg-primary-100 rounded-lg flex items-center justify-center text-primary-600 font-bold text-lg">
                    {selectedForm.name?.charAt(0)}
                  </div>
                  <div>
                    <p className="font-bold text-slate-800">{selectedForm.name}</p>
                    <p className="text-sm text-slate-500">{selectedForm.studentId} • {selectedForm.course}</p>
                  </div>
                </div>

                {selectedForm.status === 'pending' && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-semibold text-slate-700 mb-1">Seat Number</label>
                        <div className="relative">
                          <Hash className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                          <input
                            value={approvalData.seatNumber}
                            onChange={(e) => setApprovalData({ ...approvalData, seatNumber: e.target.value })}
                            className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                            placeholder="A-101"
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-sm font-semibold text-slate-700 mb-1">Exam Center</label>
                        <div className="relative">
                          <MapPin className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={16} />
                          <input
                            value={approvalData.examCenter}
                            onChange={(e) => setApprovalData({ ...approvalData, examCenter: e.target.value })}
                            className="w-full pl-10 pr-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                            placeholder="Main Hall"
                          />
                        </div>
                      </div>
                    </div>

                    <div className="flex gap-3 pt-4">
                      <button
                        onClick={() => handleStatusUpdate(selectedForm.id, 'rejected')}
                        className="flex-1 px-4 py-3 border border-red-200 text-red-600 font-bold rounded-xl hover:bg-red-50 transition-colors"
                      >
                        Reject
                      </button>
                      <button
                        onClick={() => handleStatusUpdate(selectedForm.id, 'approved')}
                        className="flex-1 px-4 py-3 bg-primary-600 text-white font-bold rounded-xl hover:bg-primary-700 shadow-xl shadow-primary-200 transition-all active:scale-95"
                      >
                        Approve
                      </button>
                    </div>
                  </div>
                )}

                {selectedForm.status !== 'pending' && (
                  <div className="p-4 bg-primary-50 text-primary-700 rounded-xl border border-primary-100">
                    <p className="text-sm font-semibold">Form already {selectedForm.status}</p>
                    {selectedForm.status === 'approved' && (
                      <p className="text-xs mt-1">Seat: {selectedForm.seatNumber} • Center: {selectedForm.examCenter}</p>
                    )}
                  </div>
                )}
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};
