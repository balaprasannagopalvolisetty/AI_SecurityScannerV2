"use client"

import type React from "react"
import { Link, useLocation } from "react-router-dom"
import { Shield, Terminal as TerminalIcon, BarChart2, Search } from "react-feather"

interface NavbarProps {
  theme: "dark" | "matrix" | "blood"
  setTheme: React.Dispatch<React.SetStateAction<"dark" | "matrix" | "blood">>
}

const Navbar: React.FC<NavbarProps> = ({ theme, setTheme }) => {
  const location = useLocation()

  return (
    <nav className="navbar">
      <Link to="/" className="navbar-brand">
        <Shield size={20} />
        <span>SecurityScanner</span>
      </Link>
      <div className="navbar-nav">
        <Link to="/" className={`nav-link ${location.pathname === "/" ? "active" : ""}`}>
          <TerminalIcon size={14} style={{ marginRight: "5px" }} />
          Terminal
        </Link>
        <Link to="/dashboard" className={`nav-link ${location.pathname === "/dashboard" ? "active" : ""}`}>
          <BarChart2 size={14} style={{ marginRight: "5px" }} />
          Dashboard
        </Link>
        <Link to="/scan" className={`nav-link ${location.pathname === "/scan" ? "active" : ""}`}>
          <Search size={14} style={{ marginRight: "5px" }} />
          New Scan
        </Link>
      </div>
      <div className="theme-selector">
        <div
          className={`theme-option dark ${theme === "dark" ? "active" : ""}`}
          onClick={() => setTheme("dark")}
          title="Dark Theme"
        ></div>
        <div
          className={`theme-option matrix ${theme === "matrix" ? "active" : ""}`}
          onClick={() => setTheme("matrix")}
          title="Matrix Theme"
        ></div>
        <div
          className={`theme-option blood ${theme === "blood" ? "active" : ""}`}
          onClick={() => setTheme("blood")}
          title="Blood Theme"
        ></div>
      </div>
    </nav>
  )
}

export default Navbar

