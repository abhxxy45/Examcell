import React, { useEffect, useState } from 'react';
import { useAuth } from '../AuthContext';
import { Result } from '../types';
import { Download, GraduationCap, Award, TrendingUp } from 'lucide-react';
import { motion } from 'motion/react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { cn } from '../lib/utils';

export const StudentResults = () => {
  const { token, user } = useAuth();
  const [result, setResult] = useState<Result | null>(null);

  useEffect(() => {
    const fetchResult = async () => {
      try {
        const res = await fetch('/api/results/my', {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.ok) {
          const text = await res.text();
          if (text) {
            const data = JSON.parse(text);
            if (data && data.id) setResult(data);
          }
        }
      } catch (err) {
        console.error('Failed to fetch result:', err);
      }
    };
    fetchResult();
  }, [token]);

  const generatePDF = (action: 'download' | 'view') => {
    if (!result) return;
    const doc = new jsPDF();
    
    doc.setFontSize(20);
    doc.text('OFFICIAL MARKSHEET', 105, 20, { align: 'center' });
    
    doc.setFontSize(12);
    doc.text(`Student: ${result.name}`, 20, 40);
    doc.text(`Roll No: ${result.studentId}`, 20, 50);
    doc.text(`Course: ${result.course}`, 20, 60);
    
    const marks = JSON.parse(result.marks);
    autoTable(doc, {
      startY: 70,
      head: [['Subject', 'Marks Obtained', 'Max Marks']],
      body: Object.entries(marks).map(([sub, mark]) => [sub, mark, 100]),
    });
    
    const finalY = (doc as any).lastAutoTable.finalY || 150;
    doc.text(`Total Marks: ${result.total}`, 20, finalY + 20);
    doc.text(`Percentage: ${result.percentage.toFixed(2)}%`, 20, finalY + 30);
    doc.text(`Grade: ${result.grade}`, 20, finalY + 40);
    
    if (action === 'download') {
      doc.save('marksheet.pdf');
    } else {
      window.open(doc.output('bloburl'), '_blank');
    }
  };

  if (!result) {
    return (
      <div className="max-w-2xl mx-auto py-20 text-center">
        <div className="w-20 h-20 bg-slate-100 text-slate-400 rounded-full flex items-center justify-center mx-auto mb-6">
          <GraduationCap size={40} />
        </div>
        <h1 className="text-2xl font-bold text-slate-800">Results Not Published</h1>
        <p className="text-slate-500 mt-2">Your results for the current semester have not been processed yet. Please check back later.</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Academic Results</h1>
          <p className="text-slate-500">View your performance and download marksheet</p>
        </div>
        <div className="flex gap-4">
          <button
            onClick={() => generatePDF('view')}
            className="bg-white text-slate-700 border-2 border-slate-200 px-6 py-3 rounded-xl flex items-center gap-2 hover:bg-slate-50 transition-all active:scale-95 font-bold"
          >
            <GraduationCap size={20} />
            View Marksheet
          </button>
          <button
            onClick={() => generatePDF('download')}
            className="bg-primary-600 hover:bg-primary-700 text-white px-6 py-3 rounded-xl flex items-center gap-2 shadow-xl shadow-primary-200 transition-all active:scale-95 font-bold"
          >
            <Download size={20} />
            Download Marksheet
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 flex items-center gap-4">
          <div className="p-3 bg-primary-50 text-primary-600 rounded-xl">
            <Award size={24} />
          </div>
          <div>
            <p className="text-xs font-bold text-slate-400 uppercase">Final Grade</p>
            <p className="text-2xl font-bold text-slate-800">{result.grade}</p>
          </div>
        </div>
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 flex items-center gap-4">
          <div className="p-3 bg-emerald-50 text-emerald-600 rounded-xl">
            <TrendingUp size={24} />
          </div>
          <div>
            <p className="text-xs font-bold text-slate-400 uppercase">Percentage</p>
            <p className="text-2xl font-bold text-slate-800">{result.percentage.toFixed(2)}%</p>
          </div>
        </div>
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-slate-100 flex items-center gap-4">
          <div className="p-3 bg-indigo-50 text-indigo-600 rounded-xl">
            <GraduationCap size={24} />
          </div>
          <div>
            <p className="text-xs font-bold text-slate-400 uppercase">Total Marks</p>
            <p className="text-2xl font-bold text-slate-800">{result.total}</p>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
        <table className="w-full text-left">
          <thead className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider">
            <tr>
              <th className="px-8 py-4 font-semibold">Subject Name</th>
              <th className="px-8 py-4 font-semibold text-center">Max Marks</th>
              <th className="px-8 py-4 font-semibold text-right">Obtained Marks</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {Object.entries(JSON.parse(result.marks)).map(([subject, mark]) => (
              <tr key={subject} className="hover:bg-slate-50 transition-colors">
                <td className="px-8 py-4 font-semibold text-slate-700">{subject}</td>
                <td className="px-8 py-4 text-center text-slate-400">100</td>
                <td className="px-8 py-4 text-right">
                  <span className={cn(
                    "font-bold",
                    (mark as number) >= 40 ? "text-slate-800" : "text-red-600"
                  )}>
                    {mark as number}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
          <tfoot className="bg-slate-50/50">
            <tr>
              <td className="px-8 py-4 font-bold text-slate-800">Total Aggregate</td>
              <td className="px-8 py-4 text-center font-bold text-slate-800">{Object.keys(JSON.parse(result.marks)).length * 100}</td>
              <td className="px-8 py-4 text-right font-bold text-primary-600 text-lg">{result.total}</td>
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  );
};
