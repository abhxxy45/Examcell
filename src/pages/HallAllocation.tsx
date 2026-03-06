import React, { useEffect, useState } from 'react';
import { useAuth } from '../AuthContext';
import { Hall, SeatingAllocation } from '../types';
import { MapPin, Users, Plus, LayoutGrid, Download } from 'lucide-react';
import { motion } from 'motion/react';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

export const HallAllocation = () => {
  const { token } = useAuth();
  const [halls, setHalls] = useState<Hall[]>([]);
  const [allocations, setAllocations] = useState<SeatingAllocation[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [formData, setFormData] = useState({ roomNumber: '', capacity: 0 });

  const fetchData = async () => {
    const [hallsRes, allocRes] = await Promise.all([
      fetch('/api/halls', { headers: { Authorization: `Bearer ${token}` } }),
      fetch('/api/seating-arrangement', { headers: { Authorization: `Bearer ${token}` } })
    ]);
    setHalls(await hallsRes.json());
    setAllocations(await allocRes.json());
  };

  useEffect(() => {
    fetchData();
  }, [token]);

  const handleAddHall = async (e: React.FormEvent) => {
    e.preventDefault();
    await fetch('/api/halls', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(formData)
    });
    setIsModalOpen(false);
    fetchData();
  };

  const handleAllocate = async () => {
    try {
      const res = await fetch('/api/allocate-seats', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      
      if (res.ok) {
        alert(data.message);
        fetchData();
      } else {
        alert(data.error || 'Failed to allocate seats');
      }
    } catch (err) {
      alert('An error occurred while allocating seats');
    }
  };

  const exportPDF = (action: 'download' | 'view') => {
    const doc = new jsPDF();
    doc.text('Seating Arrangement List', 14, 15);
    autoTable(doc, {
      startY: 20,
      head: [['Room', 'Seat', 'Student Name', 'ID', 'Course']],
      body: allocations.map(a => [a.roomNumber, a.seatNumber, a.name, a.studentId, a.course]),
    });
    
    if (action === 'download') {
      doc.save('seating_arrangement.pdf');
    } else {
      window.open(doc.output('bloburl'), '_blank');
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Hall & Seat Allocation</h1>
          <p className="text-slate-500">Manage exam rooms and automate seating</p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => setIsModalOpen(true)}
            className="bg-white border border-slate-200 text-slate-700 px-4 py-2 rounded-xl flex items-center gap-2 hover:bg-slate-50"
          >
            <Plus size={20} />
            Add Hall
          </button>
          <button
            onClick={handleAllocate}
            className="bg-primary-600 text-white px-6 py-2.5 rounded-xl flex items-center gap-2 hover:bg-primary-700 shadow-xl shadow-primary-200 transition-all font-bold text-sm"
          >
            <LayoutGrid size={18} />
            Auto Allocate
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-1 space-y-4">
          <h2 className="text-lg font-bold text-slate-800">Halls</h2>
          {halls.map(hall => (
            <div key={hall.id} className="bg-white p-4 rounded-xl border border-slate-100 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-50 text-blue-600 rounded-lg">
                  <MapPin size={20} />
                </div>
                <div>
                  <p className="font-bold text-slate-800">Room {hall.roomNumber}</p>
                  <p className="text-xs text-slate-500">Capacity: {hall.capacity} seats</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-slate-800">Seating Arrangement</h2>
            {allocations.length > 0 && (
              <div className="flex gap-3">
                <button onClick={() => exportPDF('view')} className="text-slate-600 text-sm font-semibold flex items-center gap-1 hover:text-slate-900">
                  <LayoutGrid size={16} /> View PDF
                </button>
                <button onClick={() => exportPDF('download')} className="text-blue-600 text-sm font-semibold flex items-center gap-1 hover:text-blue-700">
                  <Download size={16} /> Export PDF
                </button>
              </div>
            )}
          </div>
          <div className="bg-white rounded-2xl border border-slate-100 overflow-hidden">
            <table className="w-full text-left">
              <thead className="bg-slate-50 text-slate-500 text-xs uppercase tracking-wider">
                <tr>
                  <th className="px-6 py-4">Room</th>
                  <th className="px-6 py-4">Seat</th>
                  <th className="px-6 py-4">Student</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {allocations.map(a => (
                  <tr key={a.id}>
                    <td className="px-6 py-4 font-bold text-slate-700">{a.roomNumber}</td>
                    <td className="px-6 py-4 font-mono text-blue-600">{a.seatNumber}</td>
                    <td className="px-6 py-4">
                      <p className="font-semibold text-slate-700">{a.name}</p>
                      <p className="text-xs text-slate-400">{a.studentId}</p>
                    </td>
                  </tr>
                ))}
                {allocations.length === 0 && (
                  <tr>
                    <td colSpan={3} className="px-6 py-8 text-center text-slate-400 italic">No allocations yet</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {isModalOpen && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-slate-900/40 backdrop-blur-sm" onClick={() => setIsModalOpen(false)} />
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="relative w-full max-w-sm bg-white rounded-2xl shadow-2xl p-6"
          >
            <h2 className="text-xl font-bold text-slate-800 mb-6">Add New Hall</h2>
            <form onSubmit={handleAddHall} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1">Room Number</label>
                <input
                  required
                  value={formData.roomNumber}
                  onChange={(e) => setFormData({ ...formData, roomNumber: e.target.value })}
                  className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. 101"
                />
              </div>
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1">Capacity</label>
                <input
                  required
                  type="number"
                  value={formData.capacity || 0}
                  onChange={(e) => setFormData({ ...formData, capacity: parseInt(e.target.value) || 0 })}
                  className="w-full px-4 py-2 bg-slate-50 border border-slate-200 rounded-lg outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="e.g. 30"
                />
              </div>
              <button
                type="submit"
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-xl shadow-lg shadow-blue-200"
              >
                Save Hall
              </button>
            </form>
          </motion.div>
        </div>
      )}
    </div>
  );
};
