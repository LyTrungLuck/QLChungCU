import { Container, Row, Col } from "react-bootstrap";

const Footer = () => {
  return (
    <footer className="bg-info text-light py-4 mt-auto">
      <Container>
        <Row>
          <Col md={4} className="mb-3">
            <h5>Liên hệ</h5>
            <p>Điện thoại: 0123 456 789</p>
            <p>Email: info@ecommerce.com</p>
          </Col>
          <Col md={4} className="mb-3">
            <h5>Địa chỉ</h5>
            <p>123 Đường ABC, Quận 1, Hồ Chí Minh, Việt Nam</p>
         
          </Col>
        </Row>
      </Container>
    </footer>
  );
};

export default Footer;
