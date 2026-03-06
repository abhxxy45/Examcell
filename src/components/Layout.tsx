import React from 'react';
import { Navigate, Outlet, Link, useLocation } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import { 
  LayoutDashboard, 
  Users, 
  FileText, 
  GraduationCap, 
  MapPin, 
  LogOut,
  Menu,
  X,
  CreditCard
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '../lib/utils';

const SidebarItem = ({ to, icon: Icon, label, active }: { to: string, icon: any, label: string, active: boolean, key?: string }) => (
  <Link
    to={to}
    className={cn(
      "flex items-center gap-3 px-4 py-2.5 rounded-xl transition-all duration-200",
      active 
        ? "bg-primary-600 text-white shadow-lg shadow-primary-900/40" 
        : "text-slate-400 hover:bg-white/5 hover:text-white"
    )}
  >
    <Icon size={18} />
    <span className="font-semibold text-sm">{label}</span>
  </Link>
);

export const Layout = () => {
  const { user, logout, isLoading } = useAuth();
  const location = useLocation();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);

  if (isLoading) return <div className="h-screen w-screen flex items-center justify-center">Loading...</div>;
  if (!user) return <Navigate to="/login" replace />;

  const adminLinks = [
    { to: "/admin", icon: LayoutDashboard, label: "Dashboard" },
    { to: "/admin/students", icon: Users, label: "Students" },
    { to: "/admin/exam-forms", icon: FileText, label: "Exam Forms" },
    { to: "/admin/results", icon: GraduationCap, label: "Results" },
    { to: "/admin/halls", icon: MapPin, label: "Hall Allocation" },
  ];

  const studentLinks = [
    { to: "/student", icon: LayoutDashboard, label: "Dashboard" },
    { to: "/student/fees", icon: CreditCard, label: "Fees Payment" },
    { to: "/student/exam-form", icon: FileText, label: "Exam Form" },
    { to: "/student/hall-ticket", icon: FileText, label: "Hall Ticket" },
    { to: "/student/results", icon: GraduationCap, label: "Results" },
  ];

  const links = user.role === 'admin' ? adminLinks : studentLinks;

  return (
    <div className="min-h-screen bg-[#F8FAFC] flex">
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex flex-col w-64 bg-slate-900 text-slate-300 border-r border-slate-800 p-5">
        <div className="mb-10 px-2">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 bg-primary-500 rounded-lg flex items-center justify-center text-white shadow-lg shadow-primary-900/20">
              <GraduationCap size={20} />
            </div>
            <h1 className="text-xl font-bold tracking-tight text-white">ExamCell</h1>
          </div>
          <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mt-2">Academic Portal</p>
        </div>
        
        <nav className="flex-1 space-y-1">
          {links.map((link) => (
            <SidebarItem 
              key={link.to} 
              to={link.to}
              icon={link.icon}
              label={link.label}
              active={location.pathname === link.to} 
            />
          ))}
        </nav>

        <div className="mt-auto pt-4 border-t border-slate-800">
          <div className="px-4 py-3 mb-4">
            <p className="text-sm font-semibold text-white truncate">{user.name}</p>
            <p className="text-xs text-slate-500 truncate capitalize">{user.role}</p>
          </div>
          <button
            onClick={logout}
            className="flex items-center gap-3 px-4 py-3 w-full text-left text-slate-400 hover:bg-white/5 hover:text-white rounded-lg transition-colors"
          >
            <LogOut size={20} />
            <span className="font-medium">Logout</span>
          </button>
        </div>
      </aside>

      {/* Mobile Header */}
      <div className="md:hidden fixed top-0 left-0 right-0 bg-white/80 backdrop-blur-md border-b border-slate-200/60 z-50 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 bg-primary-600 rounded-lg flex items-center justify-center text-white">
            <GraduationCap size={16} />
          </div>
          <h1 className="text-lg font-bold text-slate-900">ExamCell</h1>
        </div>
        <button onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)} className="p-2 text-slate-600">
          {isMobileMenuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </div>

      {/* Mobile Sidebar Overlay */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMobileMenuOpen(false)}
              className="fixed inset-0 bg-black/20 backdrop-blur-sm z-40 md:hidden"
            />
            <motion.aside
              initial={{ x: "-100%" }}
              animate={{ x: 0 }}
              exit={{ x: "-100%" }}
              className="fixed top-0 left-0 bottom-0 w-64 bg-white z-50 p-4 md:hidden"
            >
               <div className="mb-8 px-4">
                <h1 className="text-xl font-bold text-blue-700">ExamCell</h1>
              </div>
              <nav className="space-y-1">
                {links.map((link) => (
                  <SidebarItem 
                    key={link.to} 
                    to={link.to}
                    icon={link.icon}
                    label={link.label}
                    active={location.pathname === link.to} 
                  />
                ))}
              </nav>
              <button
                onClick={logout}
                className="flex items-center gap-3 px-4 py-3 mt-8 w-full text-left text-red-500 hover:bg-red-50 rounded-lg"
              >
                <LogOut size={20} />
                <span className="font-medium">Logout</span>
              </button>
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <main className="flex-1 p-4 md:p-8 mt-14 md:mt-0 overflow-auto">
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <Outlet />
        </motion.div>
      </main>
    </div>
  );
};
