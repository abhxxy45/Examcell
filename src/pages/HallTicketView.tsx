import React, { useEffect, useState } from 'react';
import { useAuth } from '../AuthContext';
import { ExamForm } from '../types';
import { Download, MapPin, Hash, User, Calendar } from 'lucide-react';
import { motion } from 'motion/react';
import jsPDF from 'jspdf';
import { cn } from '../lib/utils';

export const HallTicketView = () => {
  const { token, user } = useAuth();
  const [form, setForm] = useState<ExamForm | null>(null);

  useEffect(() => {
    const fetchForm = async () => {
      try {
        const res = await fetch('/api/exam-forms/my', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.ok) {
          const text = await res.text();
          if (text) {
            const data = JSON.parse(text);
            if (data && data.id) setForm(data);
          }
        }
      } catch (err) {
        console.error('Failed to fetch form:', err);
      }
    };
    fetchForm();
  }, [token]);

  const generatePDF = (action: 'download' | 'view') => {
    if (!form) return;
    const doc = new jsPDF();
    
    // Header
    doc.setFillColor(71, 102, 237); // Primary color
    doc.rect(0, 0, 210, 40, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(22);
    doc.text('EXAM HALL TICKET', 105, 25, { align: 'center' });
    
    // Body
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(12);
    doc.text(`Student Name: ${form.name}`, 20, 60);
    doc.text(`Roll Number: ${form.studentId}`, 20, 70);
    doc.text(`Course: ${form.course}`, 20, 80);
    doc.text(`Year: ${form.year}`, 20, 90);
    
    doc.setDrawColor(200, 200, 200);
    doc.line(20, 100, 190, 100);
    
    doc.setFontSize(14);
    doc.text('Examination Details', 20, 115);
    doc.setFontSize(12);
    doc.text(`Seat Number: ${form.seatNumber}`, 20, 130);
    doc.text(`Exam Center: ${form.examCenter}`, 20, 140);
    
    doc.text('Subjects:', 20, 155);
    const subjects = JSON.parse(form.subjects);
    subjects.forEach((s: string, i: number) => {
      doc.text(`- ${s}`, 30, 165 + (i * 10));
    });
    
    doc.setFontSize(10);
    doc.setTextColor(150, 150, 150);
    doc.text('Note: Please carry this hall ticket and a valid ID card to the exam center.', 105, 280, { align: 'center' });
    
    if (action === 'download') {
      doc.save('hall_ticket.pdf');
    } else {
      window.open(doc.output('bloburl'), '_blank');
    }
  };

  if (!form || form.status !== 'approved') {
    return (
      <div className="max-w-2xl mx-auto py-20 text-center">
        <div className="w-20 h-20 bg-slate-100 text-slate-400 rounded-full flex items-center justify-center mx-auto mb-6">
          <Calendar size={40} />
        </div>
        <h1 className="text-2xl font-bold text-slate-800">Hall Ticket Not Available</h1>
        <p className="text-slate-500 mt-2">Your hall ticket will be generated once your exam form is approved by the admin.</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Hall Ticket</h1>
          <p className="text-slate-500">Download and print your official hall ticket</p>
        </div>
        <div className="flex gap-4">
          <button
            onClick={() => generatePDF('view')}
            className="bg-white text-slate-700 border-2 border-slate-200 px-6 py-3 rounded-xl flex items-center gap-2 hover:bg-slate-50 transition-all active:scale-95 font-bold"
          >
            <User size={20} />
            View Hall Ticket
          </button>
          <button
            onClick={() => generatePDF('download')}
            className="bg-primary-600 hover:bg-primary-700 text-white px-6 py-3 rounded-xl flex items-center gap-2 shadow-xl shadow-primary-200 transition-all active:scale-95 font-bold"
          >
            <Download size={20} />
            Download PDF
          </button>
        </div>
      </div>

      <div className="bg-white rounded-3xl shadow-xl overflow-hidden border border-slate-100">
        <div className="bg-primary-600 p-8 text-white flex justify-between items-center">
          <div>
            <h2 className="text-2xl font-bold">University Examination</h2>
            <p className="opacity-80">Semester End Exams • 2025</p>
          </div>
          <div className="w-24 h-24 bg-white/20 backdrop-blur-md rounded-2xl flex items-center justify-center">
            <Hash size={40} />
          </div>
        </div>

        <div className="p-8 grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="md:col-span-1">
            <div className="space-y-4">
              <div className="p-4 bg-slate-50 rounded-xl">
                <p className="text-[10px] font-bold text-slate-400 uppercase mb-1">Seat Number</p>
                <p className="text-xl font-bold text-primary-600">{form.seatNumber}</p>
              </div>
              <div className="p-4 bg-slate-50 rounded-xl">
                <p className="text-[10px] font-bold text-slate-400 uppercase mb-1">Exam Center</p>
                <p className="text-sm font-bold text-slate-700">{form.examCenter}</p>
              </div>
            </div>
          </div>

          <div className="md:col-span-2 space-y-8">
            <div className="grid grid-cols-2 gap-6">
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase mb-1">Student Name</p>
                <p className="font-bold text-slate-800">{form.name}</p>
              </div>
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase mb-1">Roll Number</p>
                <p className="font-bold text-slate-800">{form.studentId}</p>
              </div>
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase mb-1">Course</p>
                <p className="font-bold text-slate-800">{form.course}</p>
              </div>
              <div>
                <p className="text-xs font-bold text-slate-400 uppercase mb-1">Year</p>
                <p className="font-bold text-slate-800">{form.year}th Year</p>
              </div>
            </div>

            <div>
              <p className="text-xs font-bold text-slate-400 uppercase mb-4">Registered Subjects</p>
              <div className="grid grid-cols-1 gap-2">
                {JSON.parse(form.subjects).map((s: string) => (
                  <div key={s} className="flex items-center gap-3 p-3 bg-slate-50 rounded-lg">
                    <div className="w-2 h-2 rounded-full bg-primary-500" />
                    <span className="text-sm font-semibold text-slate-700">{s}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-6 border-t border-slate-100">
              <p className="text-[10px] text-slate-400 leading-relaxed">
                * This is a computer-generated document. No signature is required. <br />
                * Candidates must report to the exam center 30 minutes before the scheduled time. <br />
                * Electronic gadgets are strictly prohibited inside the examination hall.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
