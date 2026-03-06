export interface User {
  id: number;
  studentId?: string;
  name: string;
  course?: string;
  year?: string;
  email: string;
  role: 'admin' | 'student';
  feeStatus?: 'paid' | 'unpaid';
  registeredSubjects?: string; // JSON string
}

export interface ExamForm {
  id: number;
  userId: number;
  subjects: string; // JSON string
  status: 'pending' | 'approved' | 'rejected';
  seatNumber?: string;
  examCenter?: string;
  name?: string;
  studentId?: string;
  course?: string;
  year?: string;
}

export interface Result {
  id: number;
  userId: number;
  marks: string; // JSON string
  total: number;
  percentage: number;
  grade: string;
  name?: string;
  studentId?: string;
  course?: string;
  year?: string;
}

export interface Hall {
  id: number;
  roomNumber: string;
  capacity: number;
}

export interface SeatingAllocation {
  id: number;
  hallId: number;
  userId: number;
  seatNumber: string;
  roomNumber?: string;
  name?: string;
  studentId?: string;
  course?: string;
}
