// src/App.tsx

import React, { useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Terminal from "./components/Terminal";
import Dashboard from "./components/Dashboard";
import ScanForm from "./components/ScanForm";
import ScanResults from "./components/ScanResults";
import Navbar from "./components/Navbar";
import "./App.css";

const App: React.FC = () => {
  const [theme, setTheme] = useState<"dark" | "matrix" | "blood">("matrix");

  return (
    <Router>
      <div className={`app ${theme}`}>
        <Navbar theme={theme} setTheme={setTheme} />
        <div className="container">
          <Routes>
            <Route path="/" element={<Terminal />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/scan" element={<ScanForm />} />
            <Route path="/results/:scanId" element={<ScanResults />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
};

export default App;