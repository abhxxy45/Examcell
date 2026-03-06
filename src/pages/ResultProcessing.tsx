import React, { useEffect, useState } from 'react';
import { useAuth } from '../AuthContext';
import { Result, User } from '../types';
import { Plus, GraduationCap, Download, Search } from 'lucide-react';
import { motion } from 'motion/react';

export const ResultProcessing = () => {
  const { token } = useAuth();
  const [students, setStudents] = useState<User[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedStudent, setSelectedStudent] = useState<string>('');
  const [marks, setMarks] = useState<Record<string, number>>({});

  useEffect(() => {
    const fetchStudents = async () => {
      const res = await fetch('/api/users/students', {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      setStudents(data);
    };
    fetchStudents();
  }, [token]);

  const handleStudentChange = (studentId: string) => {
    setSelectedStudent(studentId);
    const student = students.find(s => s.id.toString() === studentId);
    if (student) {
      try {
        const subjects = JSON.parse(student.registeredSubjects || '[]');
        const initialMarks: Record<string, number> = {};
        subjects.forEach((sub: string) => {
          initialMarks[sub] = 0;
        });
        setMarks(initialMarks);
      } catch (e) {
        console.error('Failed to parse subjects:', e);
        setMarks({});
      }
    } else {
      setMarks({});
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (Object.keys(marks).length === 0) {
      alert('This student has no registered subjects.');
      return;
    }

    const res = await fetch('/api/results', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ userId: parseInt(selectedStudent), marks })
    });

    if (res.ok) {
      setIsModalOpen(false);
      setSelectedStudent('');
      setMarks({});
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Result Processing</h1>
          <p className="text-slate-500">Enter marks and generate marksheets</p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="bg-primary-600 hover:bg-primary-700 text-white px-6 py-2.5 rounded-xl flex items-center gap-2 shadow-xl shadow-primary-200 transition-all font-bold text-sm"
        >
          <Plus size={18} />
          Enter Marks
        </button>
      </div>

      <div className="bg-white p-8 rounded-2xl shadow-sm border border-slate-100 text-center">
        <div className="max-w-md mx-auto">
          <div className="w-20 h-20 bg-blue-50 text-blue-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <GraduationCap size={40} />
          </div>
          <h2 className="text-xl font-bold text-slate-800">Process Results</h2>
          <p className="text-slate-500 mt-2 mb-6">Select a student and enter their subject-wise marks to calculate their final grade and percentage.</p>
          <button
             onClick={() => setIsModalOpen(true)}
             className="text-blue-600 font-semibold hover:underline"
          >
            Get Started
          </button>
        </div>
      </div>

      {isModalOpen && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-slate-900/40 backdrop-blur-sm" onClick={() => setIsModalOpen(false)} />
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="relative w-full max-w-lg bg-white rounded-2xl shadow-2xl p-6"
          >
            <h2 className="text-xl font-bold text-slate-800 mb-6">Enter Student Marks</h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1">Select Student</label>
                <select
                  required
                  value={selectedStudent}
                  onChange={(e) => handleStudentChange(e.target.value)}
                  className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">Choose a student...</option>
                  {students.map(s => (
                    <option key={s.id} value={s.id}>{s.name} ({s.studentId})</option>
                  ))}
                </select>
              </div>

              <div className="space-y-3 max-h-60 overflow-y-auto pr-2">
                {Object.keys(marks).length > 0 ? (
                  Object.keys(marks).map(subject => (
                    <div key={subject} className="flex items-center justify-between gap-4">
                      <label className="text-sm font-medium text-slate-600">{subject}</label>
                      <input
                        type="number"
                        min="0"
                        max="100"
                        required
                        value={marks[subject] || 0}
                        onChange={(e) => setMarks({ ...marks, [subject]: parseInt(e.target.value) || 0 })}
                        className="w-24 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-blue-500 text-center"
                      />
                    </div>
                  ))
                ) : (
                  <div className="py-8 text-center text-slate-400 italic text-sm">
                    {selectedStudent ? 'No subjects registered for this student.' : 'Select a student to see their subjects.'}
                  </div>
                )}
              </div>

              <div className="pt-4">
                <button
                  type="submit"
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-xl shadow-lg shadow-blue-200"
                >
                  Save & Process Result
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </div>
  );
};
