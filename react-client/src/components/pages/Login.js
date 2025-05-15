import React, { useState } from "react";
import { Form, Button, Container, Row, Col, Card, Alert } from "react-bootstrap";
import { useNavigate } from "react-router-dom";

function Login() {
  const [credentials, setCredentials] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setCredentials({ ...credentials, [name]: value });
    setError(""); // Xóa thông báo lỗi khi người dùng thay đổi thông tin
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const { username, password } = credentials;

    // Kiểm tra thông tin đăng nhập
    if (username === "123" && password === "123") {
      // Đăng nhập thành công, chuyển hướng đến trang Home
      navigate("/");
    } else {
      // Đăng nhập thất bại, hiển thị thông báo lỗi
      setError("Sai tên đăng nhập hoặc mật khẩu.");
    }
  };

  return (
    <Container className="d-flex justify-content-center align-items-center min-vh-100">
      <Row className="w-100">
        <Col md={{ span: 6, offset: 3 }}>
          <Card className="shadow">
            <Card.Body>
              <h2 className="mb-4 text-center">Đăng nhập</h2>
              {error && <Alert variant="danger">{error}</Alert>}
              <Form onSubmit={handleSubmit}>
                <Form.Group className="mb-3" controlId="formUsername">
                  <Form.Label>Tên người dùng</Form.Label>
                  <Form.Control
                    type="text"
                    name="username"
                    placeholder="Nhập tên người dùng"
                    value={credentials.username}
                    onChange={handleChange}
                    required
                  />
                </Form.Group>

                <Form.Group className="mb-3" controlId="formPassword">
                  <Form.Label>Mật khẩu</Form.Label>
                  <Form.Control
                    type="password"
                    name="password"
                    placeholder="Nhập mật khẩu"
                    value={credentials.password}
                    onChange={handleChange}
                    required
                  />
                </Form.Group>

                <Button variant="primary" type="submit" className="w-100">
                  Đăng nhập
                </Button>
              </Form>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
}

export default Login;
