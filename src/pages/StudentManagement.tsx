import React, { useEffect, useState } from 'react';
import { useAuth } from '../AuthContext';
import { User } from '../types';
import { cn } from '../lib/utils';
import { Plus, Search, Edit2, Trash2, X, CheckCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { COURSES, COURSE_SUBJECTS } from '../constants';

export const StudentManagement = () => {
  const { token } = useAuth();
  const [students, setStudents] = useState<User[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingStudent, setEditingStudent] = useState<User | null>(null);
  const [formData, setFormData] = useState({
    studentId: '',
    name: '',
    course: '',
    year: '',
    email: '',
    password: '',
    feeStatus: 'unpaid' as 'paid' | 'unpaid',
    registeredSubjects: [] as string[]
  });

  const fetchStudents = async () => {
    const res = await fetch('/api/users/students', {
      headers: { Authorization: `Bearer ${token}` }
    });
    const data = await res.json();
    setStudents(data);
  };

  useEffect(() => {
    fetchStudents();
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const url = editingStudent 
      ? `/api/users/students/${editingStudent.id}` 
      : '/api/users/students';
    const method = editingStudent ? 'PUT' : 'POST';

    try {
      const res = await fetch(url, {
        method,
        headers: { 
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(formData)
      });

      if (res.ok) {
        setIsModalOpen(false);
        setEditingStudent(null);
        setFormData({ 
          studentId: '', 
          name: '', 
          course: '', 
          year: '', 
          email: '', 
          password: '',
          feeStatus: 'unpaid',
          registeredSubjects: []
        });
        fetchStudents();
      } else {
        const err = await res.json();
        alert(err.error || 'Failed to save student');
      }
    } catch (err) {
      alert('An error occurred. Please try again.');
    }
  };

  const handleDelete = async (id: number) => {
    if (confirm('Are you sure you want to delete this student?')) {
      await fetch(`/api/users/students/${id}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchStudents();
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Student Management</h1>
          <p className="text-slate-500">Add, update or remove student records</p>
        </div>
        <button
          onClick={() => {
            setEditingStudent(null);
            setFormData({ 
              studentId: '', 
              name: '', 
              course: '', 
              year: '', 
              email: '', 
              password: '',
              feeStatus: 'unpaid',
              registeredSubjects: []
            });
            setIsModalOpen(true);
          }}
          className="bg-primary-600 hover:bg-primary-700 text-white px-6 py-2.5 rounded-xl flex items-center gap-2 shadow-xl shadow-primary-200 transition-all active:scale-95 font-bold text-sm"
        >
          <Plus size={18} />
          Add Student
        </button>
      </div>

      <div className="bg-white rounded-3xl shadow-sm border border-slate-200/60 overflow-hidden">
        <div className="p-6 border-b border-slate-100 bg-slate-50/30">
          <div className="relative max-w-md">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
            <input
              type="text"
              placeholder="Search by name or ID..."
              className="w-full pl-12 pr-4 py-3 bg-white border border-slate-200 rounded-2xl focus:ring-2 focus:ring-primary-500 outline-none transition-all text-sm"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="bg-slate-50/50 text-slate-400 text-[10px] uppercase tracking-[0.15em] font-bold">
                <th className="px-8 py-5">Student ID</th>
                <th className="px-8 py-5">Name</th>
                <th className="px-8 py-5">Course & Year</th>
                <th className="px-8 py-5">Fee Status</th>
                <th className="px-8 py-5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {students.map((student) => (
                <tr key={student.id} className="hover:bg-slate-50/80 transition-colors group">
                  <td className="px-8 py-5">
                    <span className="font-mono text-xs font-bold text-primary-600 bg-primary-50 px-2 py-1 rounded-md">
                      {student.studentId}
                    </span>
                  </td>
                  <td className="px-8 py-5 font-bold text-slate-700">{student.name}</td>
                  <td className="px-8 py-5 text-sm text-slate-500">
                    <span className="font-medium">{student.course}</span>
                    <span className="mx-2 text-slate-300">•</span>
                    <span className="text-xs bg-slate-100 px-2 py-0.5 rounded-full font-bold">YR {student.year}</span>
                  </td>
                  <td className="px-8 py-5">
                    <span className={cn(
                      "px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest",
                      student.feeStatus === 'paid' ? "bg-emerald-100 text-emerald-700" : "bg-red-100 text-red-700"
                    )}>
                      {student.feeStatus}
                    </span>
                  </td>
                  <td className="px-8 py-5 text-right">
                    <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button
                        onClick={() => {
                          setEditingStudent(student);
                          setFormData({
                            studentId: student.studentId || '',
                            name: student.name,
                            course: student.course || '',
                            year: student.year || '',
                            email: student.email,
                            password: '',
                            feeStatus: student.feeStatus || 'unpaid',
                            registeredSubjects: student.registeredSubjects ? JSON.parse(student.registeredSubjects) : []
                          });
                          setIsModalOpen(true);
                        }}
                        className="p-2 text-slate-400 hover:text-primary-600 hover:bg-primary-50 rounded-xl transition-all"
                      >
                        <Edit2 size={16} />
                      </button>
                      <button
                        onClick={() => handleDelete(student.id)}
                        className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-xl transition-all"
                      >
                        <Trash2 size={16} />
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
        {isModalOpen && (
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
                <h2 className="text-xl font-bold text-slate-800">
                  {editingStudent ? 'Edit Student' : 'Add New Student'}
                </h2>
                <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-slate-600">
                  <X size={24} />
                </button>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Student ID</label>
                    <input
                      required
                      value={formData.studentId}
                      onChange={(e) => setFormData({ ...formData, studentId: e.target.value })}
                      className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                      placeholder="STU001"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Full Name</label>
                    <input
                      required
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                      placeholder="John Doe"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Course</label>
                    <select
                      required
                      value={formData.course}
                      onChange={(e) => {
                        const course = e.target.value;
                        setFormData({ 
                          ...formData, 
                          course,
                          registeredSubjects: [] // Reset subjects on course change
                        });
                      }}
                      className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                    >
                      <option value="">Select Course</option>
                      {COURSES.map(course => (
                        <option key={course} value={course}>{course}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Year</label>
                    <select
                      required
                      value={formData.year}
                      onChange={(e) => {
                        const year = e.target.value;
                        setFormData({ 
                          ...formData, 
                          year,
                          registeredSubjects: [] // Reset subjects on year change
                        });
                      }}
                      className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                    >
                      <option value="">Select Year</option>
                      <option value="1">1st Year</option>
                      <option value="2">2nd Year</option>
                      <option value="3">3rd Year</option>
                      <option value="4">4th Year</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Email Address</label>
                    <input
                      required
                      type="email"
                      value={formData.email}
                      onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                      className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                      placeholder="john@example.com"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Fee Status</label>
                    <select
                      required
                      value={formData.feeStatus}
                      onChange={(e) => setFormData({ ...formData, feeStatus: e.target.value as 'paid' | 'unpaid' })}
                      className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                    >
                      <option value="unpaid">Unpaid</option>
                      <option value="paid">Paid</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-2">Registered Subjects</label>
                  <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto p-2 bg-slate-50 rounded-xl border border-slate-200">
                    {formData.course && formData.year ? (
                      (COURSE_SUBJECTS[formData.course]?.[formData.year] || []).map(subject => (
                        <button
                          key={subject}
                          type="button"
                          onClick={() => {
                            const current = formData.registeredSubjects;
                            setFormData({
                              ...formData,
                              registeredSubjects: current.includes(subject)
                                ? current.filter(s => s !== subject)
                                : [...current, subject]
                            });
                          }}
                          className={cn(
                            "flex items-center gap-2 px-3 py-2 rounded-lg text-[10px] font-bold transition-all border",
                            formData.registeredSubjects.includes(subject)
                              ? "bg-primary-50 border-primary-500 text-primary-700"
                              : "bg-white border-slate-200 text-slate-500 hover:border-slate-300"
                          )}
                        >
                          <div className={cn(
                            "w-3 h-3 rounded-sm border flex items-center justify-center shrink-0",
                            formData.registeredSubjects.includes(subject) ? "bg-primary-500 border-primary-500 text-white" : "border-slate-300"
                          )}>
                            {formData.registeredSubjects.includes(subject) && <CheckCircle size={8} />}
                          </div>
                          <span className="truncate">{subject}</span>
                        </button>
                      ))
                    ) : (
                      <div className="col-span-2 py-4 text-center text-slate-400 text-xs italic">
                        Please select course and year first
                      </div>
                    )}
                  </div>
                </div>

                {!editingStudent && (
                  <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-1">Password</label>
                    <input
                      required
                      type="password"
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-primary-500"
                      placeholder="••••••••"
                    />
                  </div>
                )}

                <div className="pt-4">
                  <button
                    type="submit"
                    className="w-full bg-primary-600 hover:bg-primary-700 text-white font-bold py-3 rounded-xl shadow-lg shadow-primary-200 transition-all active:scale-[0.98]"
                  >
                    {editingStudent ? 'Update Student' : 'Create Student'}
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};
