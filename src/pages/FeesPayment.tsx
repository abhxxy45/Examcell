import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../AuthContext';
import { CreditCard, CheckCircle, AlertCircle, Loader2, ShieldCheck, Wallet, Download } from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '../lib/utils';
import jsPDF from 'jspdf';

export const FeesPayment = () => {
  const { token } = useAuth();
  const receiptRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(true);
  const [paying, setPaying] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [userProfile, setUserProfile] = useState<any>(null);
  const [paymentSuccess, setPaymentSuccess] = useState(false);

  const fetchProfile = async () => {
    try {
      const res = await fetch('/api/users/me', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setUserProfile(data);
      }
    } catch (err) {
      console.error('Failed to fetch profile:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, [token]);

  const generateReceiptPDF = (action: 'download' | 'view') => {
    try {
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pageWidth = pdf.internal.pageSize.getWidth();
      
      // Header
      pdf.setFillColor(37, 99, 235); // Primary 600
      pdf.rect(0, 0, pageWidth, 40, 'F');
      
      pdf.setTextColor(255, 255, 255);
      pdf.setFontSize(24);
      pdf.setFont('helvetica', 'bold');
      pdf.text('PAYMENT RECEIPT', pageWidth / 2, 25, { align: 'center' });
      
      // Content
      pdf.setTextColor(30, 41, 59); // Slate 800
      pdf.setFontSize(12);
      pdf.setFont('helvetica', 'normal');
      
      let y = 60;
      const margin = 20;
      const colWidth = (pageWidth - 2 * margin) / 2;

      // Student Info Box
      pdf.setDrawColor(226, 232, 240); // Slate 200
      pdf.setFillColor(248, 250, 252); // Slate 50
      pdf.roundedRect(margin, y, pageWidth - 2 * margin, 40, 3, 3, 'FD');
      
      pdf.setFontSize(10);
      pdf.setTextColor(100, 116, 139); // Slate 500
      pdf.text('STUDENT NAME', margin + 5, y + 10);
      pdf.text('STUDENT ID', margin + colWidth + 5, y + 10);
      pdf.text('COURSE', margin + 5, y + 25);
      pdf.text('YEAR', margin + colWidth + 5, y + 25);
      
      pdf.setFontSize(11);
      pdf.setTextColor(30, 41, 59); // Slate 800
      pdf.setFont('helvetica', 'bold');
      pdf.text(userProfile?.name || 'N/A', margin + 5, y + 15);
      pdf.text(userProfile?.studentId || 'N/A', margin + colWidth + 5, y + 15);
      pdf.text(userProfile?.course || 'N/A', margin + 5, y + 30);
      pdf.text(`${userProfile?.year || 'N/A'} Year`, margin + colWidth + 5, y + 30);
      
      y += 60;
      
      // Payment Details
      pdf.setFontSize(14);
      pdf.text('Payment Details', margin, y);
      y += 10;
      
      pdf.setFontSize(11);
      pdf.setFont('helvetica', 'normal');
      pdf.setTextColor(100, 116, 139);
      
      const details = [
        ['Transaction ID', `TXN-${Math.random().toString(36).substr(2, 9).toUpperCase()}`],
        ['Amount Paid', 'Rs. 45,000.00'],
        ['Payment Date', new Date().toLocaleDateString()],
        ['Status', 'Completed']
      ];
      
      details.forEach(([label, value]) => {
        pdf.setTextColor(100, 116, 139);
        pdf.text(label, margin, y);
        pdf.setTextColor(30, 41, 59);
        pdf.setFont('helvetica', 'bold');
        pdf.text(value, pageWidth - margin, y, { align: 'right' });
        pdf.setDrawColor(241, 245, 249);
        pdf.line(margin, y + 2, pageWidth - margin, y + 2);
        y += 12;
        pdf.setFont('helvetica', 'normal');
      });
      
      // Footer
      y = 270;
      pdf.setFontSize(9);
      pdf.setTextColor(148, 163, 184);
      pdf.text('Computer Generated Receipt - No Signature Required', pageWidth / 2, y, { align: 'center' });
      pdf.text('Academic Management System', pageWidth / 2, y + 5, { align: 'center' });

      if (action === 'download') {
        pdf.save(`Fee_Receipt_${userProfile?.studentId || 'Student'}.pdf`);
      } else {
        window.open(pdf.output('bloburl'), '_blank');
      }
    } catch (err) {
      console.error('Failed to generate PDF:', err);
      alert('Failed to generate PDF. Please try again.');
    }
  };

  const downloadReceipt = async () => {
    setDownloading(true);
    generateReceiptPDF('download');
    setDownloading(false);
  };

  const viewReceipt = () => {
    generateReceiptPDF('view');
  };

  const handlePayment = async () => {
    setPaying(true);
    try {
      const res = await fetch('/api/payments/pay-fees', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        }
      });

      if (res.ok) {
        setPaymentSuccess(true);
        fetchProfile();
      } else {
        const err = await res.json();
        alert(err.error || 'Payment failed');
      }
    } catch (err) {
      alert('An error occurred during payment. Please try again.');
    } finally {
      setPaying(false);
    }
  };

  if (loading) return <div className="flex items-center justify-center h-64"><Loader2 className="animate-spin text-primary-600" /></div>;

  if (userProfile?.feeStatus === 'paid') {
    return (
      <div className="max-w-2xl mx-auto py-12 text-center">
        <motion.div 
          initial={{ scale: 0.5, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          className="w-24 h-24 bg-emerald-50 text-emerald-600 rounded-full flex items-center justify-center mx-auto mb-6 shadow-xl shadow-emerald-100"
        >
          <CheckCircle size={48} />
        </motion.div>
        <h1 className="text-3xl font-bold text-slate-900">Fees Paid Successfully</h1>
        <p className="text-slate-500 mt-3 text-lg">Your academic fees for the current semester are fully settled.</p>
        
        <div ref={receiptRef} className="mt-10 p-8 bg-white rounded-[2rem] border border-slate-100 text-left shadow-2xl shadow-slate-200/50">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 bg-primary-600 rounded-lg flex items-center justify-center text-white">
                <ShieldCheck size={20} />
              </div>
              <h3 className="font-bold text-slate-800 text-xl">Payment Receipt</h3>
            </div>
            <span className="px-4 py-1.5 bg-emerald-100 text-emerald-700 rounded-full text-xs font-bold uppercase tracking-widest">Verified</span>
          </div>
          
          <div className="mb-8 p-4 bg-slate-50 rounded-2xl border border-slate-100">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Student Name</p>
                <p className="font-bold text-slate-800">{userProfile?.name}</p>
              </div>
              <div>
                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Student ID</p>
                <p className="font-bold text-slate-800">{userProfile?.studentId}</p>
              </div>
              <div>
                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Course</p>
                <p className="font-bold text-slate-800">{userProfile?.course}</p>
              </div>
              <div>
                <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Year</p>
                <p className="font-bold text-slate-800">{userProfile?.year} Year</p>
              </div>
            </div>
          </div>

          <div className="space-y-4 text-sm">
            <div className="flex justify-between py-3 border-b border-slate-50">
              <span className="text-slate-500">Transaction ID:</span> 
              <span className="font-mono font-bold text-slate-700">TXN-{Math.random().toString(36).substr(2, 9).toUpperCase()}</span>
            </div>
            <div className="flex justify-between py-3 border-b border-slate-50">
              <span className="text-slate-500">Amount Paid:</span> 
              <span className="font-bold text-slate-900 text-lg">₹45,000.00</span>
            </div>
            <div className="flex justify-between py-3 border-b border-slate-50">
              <span className="text-slate-500">Payment Date:</span> 
              <span className="font-medium text-slate-700">{new Date().toLocaleDateString()}</span>
            </div>
            <div className="flex justify-between py-3">
              <span className="text-slate-500">Status:</span> 
              <span className="font-bold text-emerald-600">Completed</span>
            </div>
          </div>
          
          <div className="mt-8 pt-8 border-t border-slate-100 text-center">
            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-widest">Computer Generated Receipt - No Signature Required</p>
          </div>
        </div>

        <div className="flex gap-4 mt-8">
          <button 
            onClick={downloadReceipt}
            disabled={downloading}
            className="flex-1 py-4 bg-slate-900 text-white rounded-2xl font-bold hover:bg-slate-800 transition-all active:scale-[0.98] flex items-center justify-center gap-2"
          >
            {downloading ? (
              <>
                <Loader2 className="animate-spin" size={20} />
                Generating PDF...
              </>
            ) : (
              <>
                <Download size={20} />
                Download Receipt
              </>
            )}
          </button>
          <button 
            onClick={viewReceipt}
            className="flex-1 py-4 bg-white text-slate-900 border-2 border-slate-200 rounded-2xl font-bold hover:bg-slate-50 transition-all active:scale-[0.98] flex items-center justify-center gap-2"
          >
            <ShieldCheck size={20} />
            View Receipt
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="mb-10">
        <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Academic Fees Payment</h1>
        <p className="text-slate-500 mt-2 text-lg">Complete your semester fee payment to unlock exam registration.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-white p-8 rounded-[2rem] shadow-xl shadow-slate-200/40 border border-slate-100">
            <h2 className="text-xl font-bold text-slate-800 mb-8 flex items-center gap-3">
              <Wallet className="text-primary-600" size={24} />
              Fee Breakdown
            </h2>
            <div className="space-y-5">
              <div className="flex justify-between items-center p-4 bg-slate-50 rounded-2xl">
                <div>
                  <p className="font-bold text-slate-800">Tuition Fees</p>
                  <p className="text-xs text-slate-400">Semester 4 - B.Tech IT</p>
                </div>
                <span className="font-bold text-slate-700">₹35,000.00</span>
              </div>
              <div className="flex justify-between items-center p-4 bg-slate-50 rounded-2xl">
                <div>
                  <p className="font-bold text-slate-800">Exam Fees</p>
                  <p className="text-xs text-slate-400">Semester End Examinations</p>
                </div>
                <span className="font-bold text-slate-700">₹5,000.00</span>
              </div>
              <div className="flex justify-between items-center p-4 bg-slate-50 rounded-2xl">
                <div>
                  <p className="font-bold text-slate-800">Library & Lab Fees</p>
                  <p className="text-xs text-slate-400">Annual Maintenance</p>
                </div>
                <span className="font-bold text-slate-700">₹5,000.00</span>
              </div>
              <div className="pt-6 border-t border-slate-100 flex justify-between items-center">
                <span className="text-xl font-bold text-slate-900">Total Amount Due</span>
                <span className="text-3xl font-black text-primary-600">₹45,000.00</span>
              </div>
            </div>
          </div>

          <div className="bg-primary-600 p-8 rounded-[2rem] text-white shadow-2xl shadow-primary-200 relative overflow-hidden">
            <div className="relative z-10">
              <h3 className="text-xl font-bold mb-4 flex items-center gap-2">
                <ShieldCheck size={24} />
                Secure Payment
              </h3>
              <p className="text-primary-100 text-sm leading-relaxed mb-6">
                Your payment is processed through a secure encrypted gateway. We do not store your card details.
              </p>
              <div className="flex gap-4">
                <div className="bg-white/20 px-4 py-2 rounded-xl text-xs font-bold backdrop-blur-sm">SSL SECURED</div>
                <div className="bg-white/20 px-4 py-2 rounded-xl text-xs font-bold backdrop-blur-sm">PCI COMPLIANT</div>
              </div>
            </div>
            <div className="absolute -right-10 -bottom-10 w-48 h-48 bg-white/10 rounded-full blur-3xl" />
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-white p-8 rounded-[2rem] shadow-xl shadow-slate-200/40 border border-slate-100 sticky top-8">
            <h2 className="text-xl font-bold text-slate-800 mb-8 flex items-center gap-3">
              <CreditCard className="text-primary-600" size={24} />
              Checkout
            </h2>
            
            <div className="space-y-6">
              <div className="p-4 bg-amber-50 rounded-2xl border border-amber-100 flex gap-3">
                <AlertCircle className="text-amber-600 shrink-0" size={20} />
                <p className="text-xs text-amber-800 font-medium leading-relaxed">
                  Payment is mandatory to apply for the upcoming semester exams.
                </p>
              </div>

              <div className="space-y-4">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-500">Subtotal</span>
                  <span className="font-bold text-slate-700">₹45,000.00</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-500">Processing Fee</span>
                  <span className="font-bold text-slate-700">₹0.00</span>
                </div>
                <div className="pt-4 border-t border-slate-100 flex justify-between items-center">
                  <span className="font-bold text-slate-900">Total</span>
                  <span className="text-xl font-black text-slate-900">₹45,000.00</span>
                </div>
              </div>

              <button
                onClick={handlePayment}
                disabled={paying}
                className="w-full bg-primary-600 hover:bg-primary-700 text-white font-bold py-5 rounded-2xl shadow-xl shadow-primary-200 transition-all active:scale-[0.98] disabled:opacity-70 flex items-center justify-center gap-3"
              >
                {paying ? (
                  <>
                    <Loader2 className="animate-spin" size={24} />
                    Processing...
                  </>
                ) : (
                  <>
                    <CreditCard size={24} />
                    Pay Fees Now
                  </>
                )}
              </button>

              <p className="text-[10px] text-center text-slate-400 font-medium">
                By clicking "Pay Fees Now", you agree to our terms of service and refund policy.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
