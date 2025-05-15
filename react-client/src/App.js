import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Login from "./components/pages/Login";
import Register from "./components/pages/Register";
import Home from "./components/pages/Home";
import ResidentDashboard from "./components/resident/Dashboard";
import AdminDashboard from "./components/admin/Dashboard";
import { Container } from "react-bootstrap";
import Header from "./components/layouts/Header";  
import Footer from "./components/layouts/Footer";  

function App() {
  return (
    <Router>
      <Header/>
      <Container>    
      <Routes>
      <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/admin/dashboard" element={<AdminDashboard />} />
        <Route path="/resident/dashboard" element={<ResidentDashboard />} />
      </Routes>
      </Container>
      <Footer/>
    </Router>
  );
}

export default App;