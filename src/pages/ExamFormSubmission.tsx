import React, { useState, useEffect } from 'react';
import { useAuth } from '../AuthContext';
import { ExamForm } from '../types';
import { FileText, Upload, CheckCircle, AlertCircle, Loader2, CreditCard } from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '../lib/utils';
import { Link } from 'react-router-dom';

export const ExamFormSubmission = () => {
  const { token, user: authUser } = useAuth();
  const [existingForm, setExistingForm] = useState<ExamForm | null>(null);
  const [userProfile, setUserProfile] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    subjects: [] as string[]
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [formRes, userRes] = await Promise.all([
          fetch('/api/exam-forms/my', {
            headers: { Authorization: `Bearer ${token}` }
          }),
          fetch('/api/users/me', {
            headers: { Authorization: `Bearer ${token}` }
          })
        ]);

        if (formRes.ok) {
          const text = await formRes.text();
          if (text) {
            const data = JSON.parse(text);
            if (data && data.id) setExistingForm(data);
          }
        }

        if (userRes.ok) {
          const data = await userRes.json();
          setUserProfile(data);
        }
      } catch (err) {
        console.error('Failed to fetch data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [token]);

  const availableSubjects = userProfile?.registeredSubjects 
    ? JSON.parse(userProfile.registeredSubjects) 
    : [];

  const toggleSubject = (subject: string) => {
    setFormData(prev => ({
      ...prev,
      subjects: prev.subjects.includes(subject)
        ? prev.subjects.filter(s => s !== subject)
        : [...prev.subjects, subject]
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (formData.subjects.length === 0) return alert('Please select at least one subject');

    setSubmitting(true);
    try {
      const res = await fetch('/api/exam-forms', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(formData)
      });

      if (res.ok) {
        // Fetch the updated form instead of reloading
        const updatedRes = await fetch('/api/exam-forms/my', {
          headers: { Authorization: `Bearer ${token}` }
        });
        const text = await updatedRes.text();
        if (text) {
          const data = JSON.parse(text);
          setExistingForm(data);
        }
      } else {
        const err = await res.json();
        alert(err.error || 'Failed to submit form');
      }
    } catch (err) {
      alert('An error occurred. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) return <div>Loading...</div>;

  if (userProfile?.feeStatus === 'unpaid') {
    return (
      <div className="max-w-2xl mx-auto py-20 text-center">
        <motion.div 
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="w-20 h-20 bg-red-50 text-red-600 rounded-full flex items-center justify-center mx-auto mb-6 shadow-xl shadow-red-100"
        >
          <AlertCircle size={40} />
        </motion.div>
        <h1 className="text-3xl font-bold text-slate-800">Fees Payment Pending</h1>
        <p className="text-slate-500 mt-4 text-lg">You cannot apply for exams until your academic fees are fully paid.</p>
        <div className="mt-10">
          <Link 
            to="/student/fees" 
            className="inline-flex items-center gap-2 bg-primary-600 hover:bg-primary-700 text-white px-8 py-4 rounded-2xl font-bold shadow-xl shadow-primary-200 transition-all active:scale-95"
          >
            <CreditCard size={20} />
            Pay Fees Now
          </Link>
        </div>
      </div>
    );
  }

  if (existingForm) {
    return (
      <div className="max-w-2xl mx-auto py-12 text-center">
        <div className="w-20 h-20 bg-emerald-50 text-emerald-600 rounded-full flex items-center justify-center mx-auto mb-6">
          <CheckCircle size={40} />
        </div>
        <h1 className="text-2xl font-bold text-slate-800">Form Already Submitted</h1>
        <p className="text-slate-500 mt-2">Your exam application is currently <span className="font-bold text-amber-600 uppercase">{existingForm.status}</span>.</p>
        <div className="mt-8 p-6 bg-white rounded-2xl border border-slate-100 text-left">
          <h3 className="font-bold text-slate-800 mb-4">Submission Details</h3>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between"><span className="text-slate-500">Subjects:</span> <span className="font-medium">{JSON.parse(existingForm.subjects).join(', ')}</span></div>
            <div className="flex justify-between"><span className="text-slate-500">Submitted on:</span> <span className="font-medium">{new Date().toLocaleDateString()}</span></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-slate-800">Exam Application Form</h1>
        <p className="text-slate-500">Fill in the details to apply for the upcoming semester exams</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-8">
        <div className="bg-white p-8 rounded-2xl shadow-sm border border-slate-100">
            <h2 className="text-lg font-bold text-slate-800 mb-6 flex items-center gap-2">
              <FileText className="text-primary-600" size={20} />
              Subject Selection
            </h2>
          {availableSubjects.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {availableSubjects.map((subject: string) => (
                    <label 
                      key={subject}
                      className={cn(
                        "flex items-center gap-3 p-4 rounded-xl border-2 cursor-pointer transition-all",
                        formData.subjects.includes(subject) 
                          ? "border-primary-500 bg-primary-50 text-primary-700" 
                          : "border-slate-100 hover:border-slate-200"
                      )}
                    >
                      <input
                        type="checkbox"
                        className="hidden"
                        checked={formData.subjects.includes(subject)}
                        onChange={() => toggleSubject(subject)}
                      />
                      <div className={cn(
                        "w-5 h-5 rounded border-2 flex items-center justify-center",
                        formData.subjects.includes(subject) ? "border-primary-500 bg-primary-500 text-white" : "border-slate-300"
                      )}>
                        {formData.subjects.includes(subject) && <CheckCircle size={14} />}
                      </div>
                      <span className="font-medium">{subject}</span>
                    </label>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center bg-slate-50 rounded-xl border border-dashed border-slate-200">
              <p className="text-slate-500 italic">No subjects registered for your profile. Please contact the admin.</p>
            </div>
          )}
        </div>

        <div className="flex items-center gap-4 p-4 bg-amber-50 rounded-xl border border-amber-100 text-amber-800">
          <AlertCircle size={20} />
          <p className="text-xs font-medium">By submitting this form, I declare that all information provided is correct to the best of my knowledge.</p>
        </div>

        <button
          type="submit"
          disabled={submitting}
          className="w-full bg-primary-600 hover:bg-primary-700 text-white font-bold py-4 rounded-2xl shadow-xl shadow-primary-200 transition-all active:scale-[0.98] disabled:opacity-70 flex items-center justify-center gap-2"
        >
          {submitting ? (
            <>
              <Loader2 className="animate-spin" size={20} />
              Submitting...
            </>
          ) : (
            'Submit Exam Application'
          )}
        </button>
      </form>
    </div>
  );
};
