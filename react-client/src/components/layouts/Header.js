import React from "react";
import { Link } from "react-router-dom";
import { Navbar, Nav, Container } from "react-bootstrap";
import { FaHome, FaUserPlus, FaSignInAlt } from "react-icons/fa";

const Header = () => {
  return (
    <Navbar bg="dark" variant="dark" expand="lg" collapseOnSelect>
      <Container>
        <Navbar.Brand as={Link} to="/" className="fw-bold fs-4 text-warning">
          🛒 eCommerce
        </Navbar.Brand>
        <Navbar.Toggle aria-controls="basic-navbar-nav" />
        <Navbar.Collapse id="basic-navbar-nav">
          <Nav className="ms-auto">
            <Nav.Link as={Link} to="/" className="px-3 text-light">
              <FaHome className="me-1" />
              Trang chủ
            </Nav.Link>
            <Nav.Link as={Link} to="/register" className="px-3 text-success">
              <FaUserPlus className="me-1" />
              Đăng ký
            </Nav.Link>
            <Nav.Link as={Link} to="/login" className="px-3 text-danger">
              <FaSignInAlt className="me-1" />
              Đăng nhập
            </Nav.Link>
          </Nav>
        </Navbar.Collapse>
      </Container>
    </Navbar>
  );
};

export default Header;
