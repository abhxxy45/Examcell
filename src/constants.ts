export const COURSES = [
  'B.Sc. IT',
  'B.Sc. Computer Science',
  'B.Tech Information Technology',
  'B.Tech Computer Science',
  'B.Tech Electronics & Communication',
  'B.Tech Mechanical Engineering',
  'B.Tech Civil Engineering',
  'BCA (Bachelor of Computer Applications)',
  'MCA (Master of Computer Applications)',
  'M.Sc. Information Technology'
];

export const COURSE_SUBJECTS: Record<string, Record<string, string[]>> = {
  'B.Sc. IT': {
    '1': ['Introduction to IT', 'Programming in C', 'Digital Electronics', 'Mathematics I', 'Communication Skills'],
    '2': ['Data Structures', 'Web Technologies', 'Database Management', 'Computer Networks', 'Mathematics II'],
    '3': ['Software Engineering', 'Java Programming', 'Operating Systems', 'Information Security', 'Project Work']
  },
  'B.Sc. Computer Science': {
    '1': ['Computer Fundamentals', 'Programming in C++', 'Discrete Mathematics', 'Physics I', 'English'],
    '2': ['Data Structures', 'Computer Architecture', 'Operating Systems', 'Database Systems', 'Numerical Methods'],
    '3': ['Artificial Intelligence', 'Computer Graphics', 'Software Engineering', 'Theory of Computation', 'Final Project']
  },
  'B.Tech Information Technology': {
    '1': ['Engineering Physics', 'Engineering Chemistry', 'Basic Electrical Engineering', 'Calculus', 'Programming for Problem Solving'],
    '2': ['Data Structures', 'Digital Logic Design', 'Object Oriented Programming', 'Discrete Mathematics', 'Environmental Science'],
    '3': ['Computer Networks', 'Database Management Systems', 'Design and Analysis of Algorithms', 'Operating Systems', 'Formal Languages and Automata'],
    '4': ['Cloud Computing', 'Cyber Security', 'Machine Learning', 'Internet of Things', 'Major Project']
  },
  'B.Tech Computer Science': {
    '1': ['Engineering Physics', 'Engineering Chemistry', 'Basic Electronics', 'Linear Algebra', 'C Programming'],
    '2': ['Data Structures', 'Computer Organization', 'Object Oriented Programming', 'Discrete Structures', 'Technical Writing'],
    '3': ['Theory of Computation', 'Compiler Design', 'Operating Systems', 'Database Systems', 'Computer Networks'],
    '4': ['Artificial Intelligence', 'Machine Learning', 'Big Data Analytics', 'Distributed Systems', 'Major Project']
  },
  'B.Tech Electronics & Communication': {
    '1': ['Engineering Physics', 'Engineering Chemistry', 'Basic Electrical', 'Calculus', 'Workshop Practice'],
    '2': ['Network Analysis', 'Electronic Devices', 'Signals and Systems', 'Digital Electronics', 'Mathematics III'],
    '3': ['Analog Communication', 'Microprocessors', 'Control Systems', 'Digital Signal Processing', 'Antennas'],
    '4': ['VLSI Design', 'Embedded Systems', 'Optical Communication', 'Wireless Networks', 'Major Project']
  },
  'B.Tech Mechanical Engineering': {
    '1': ['Engineering Physics', 'Engineering Chemistry', 'Engineering Graphics', 'Calculus', 'Basic Mechanical Engineering'],
    '2': ['Thermodynamics', 'Fluid Mechanics', 'Strength of Materials', 'Kinematics of Machines', 'Material Science'],
    '3': ['Heat and Mass Transfer', 'Machine Design', 'Manufacturing Technology', 'Dynamics of Machines', 'IC Engines'],
    '4': ['CAD/CAM', 'Refrigeration and Air Conditioning', 'Automobile Engineering', 'Robotics', 'Major Project']
  },
  'B.Tech Civil Engineering': {
    '1': ['Engineering Physics', 'Engineering Chemistry', 'Engineering Mechanics', 'Calculus', 'Basic Civil Engineering'],
    '2': ['Surveying', 'Building Materials', 'Solid Mechanics', 'Fluid Mechanics', 'Mathematics III'],
    '3': ['Structural Analysis', 'Geotechnical Engineering', 'Hydrology', 'Concrete Technology', 'Transportation Engineering'],
    '4': ['Environmental Engineering', 'Design of Steel Structures', 'Construction Management', 'Irrigation Engineering', 'Major Project']
  },
  'BCA (Bachelor of Computer Applications)': {
    '1': ['Business Communication', 'Mathematical Foundation', 'Programming in C', 'PC Software', 'Accounting'],
    '2': ['Data Structures', 'Database Management', 'Object Oriented Programming', 'System Analysis', 'Statistics'],
    '3': ['Java Programming', 'Web Technologies', 'Software Engineering', 'Multimedia Systems', 'Project']
  },
  'MCA (Master of Computer Applications)': {
    '1': ['Advanced Data Structures', 'Computer Organization', 'Discrete Mathematics', 'Programming in Java', 'Management Information Systems'],
    '2': ['Object Oriented Analysis', 'Operating Systems', 'Database Management', 'Software Engineering', 'Computer Networks'],
    '3': ['Mobile Computing', 'Big Data Analytics', 'Cloud Computing', 'Network Security', 'Major Project']
  },
  'M.Sc. Information Technology': {
    '1': ['Information Security', 'Data Warehousing', 'Python Programming', 'Advanced Networking', 'Research Methodology'],
    '2': ['Internet of Things', 'Enterprise Resource Planning', 'Cloud Computing', 'Machine Learning', 'Dissertation']
  }
};
