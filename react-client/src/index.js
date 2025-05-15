import React from "react";
import ReactDOM from "react-dom/client"; // Sử dụng API mới
import App from "./App";
import 'bootstrap/dist/css/bootstrap.min.css';

const root = ReactDOM.createRoot(document.getElementById("root")); // Tạo root
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);