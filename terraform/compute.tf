# Security Group for Load Balancer
resource "aws_security_group" "alb_sg" {
  name        = "authpole-alb-sg"
  description = "Allow inbound HTTP/HTTPS traffic to ALB"
  vpc_id      = aws_vpc.authpole_vpc.id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "authpole-alb-sg"
  }
}

# Security Group for Compute Instances
resource "aws_security_group" "server_sg" {
  name        = "authpole-server-sg"
  description = "Allow traffic from ALB to Authpole instances"
  vpc_id      = aws_vpc.authpole_vpc.id

  ingress {
    description     = "Authpole Server Port from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "authpole-server-sg"
  }
}

# Application Load Balancer
resource "aws_lb" "authpole_alb" {
  name               = "authpole-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  tags = {
    Name = "authpole-alb"
  }
}

# ALB Target Group
resource "aws_lb_target_group" "authpole_tg" {
  name        = "authpole-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.authpole_vpc.id
  target_type = "instance"

  health_check {
    path                = "/healthz"
    protocol            = "HTTP"
    port                = "8080"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = {
    Name = "authpole-tg"
  }
}

# ALB HTTP Listener (Port 80 Redirect to HTTPS 443)
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.authpole_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# ALB HTTPS Listener (Port 443 with ACM Certificate for authpole.swii.sh)
resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.authpole_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.domain_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.authpole_tg.arn
  }
}

# Launch Template for Unikraft / Docker Compute Instance
resource "aws_launch_template" "authpole_lt" {
  name_prefix   = "authpole-lt-"
  image_id      = "ami-0c7217cdde317cfec" # Amazon Linux 2023 or custom Unikraft AMI
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.authpole_instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.server_sg.id]
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              exec > /var/log/user-data.log 2>&1
              echo "Starting Authpole installation..."
              yum update -y
              yum install -y golang git

              mkdir -p /opt/authpole
              cd /opt/authpole
              git clone https://github.com/authpole/authpole.git .
              go build -o authpole ./cmd/server

              cat <<'SERVICE' > /etc/systemd/system/authpole.service
              [Unit]
              Description=Authpole Mediator Proxy IDP Server
              After=network.target

              [Service]
              Type=simple
              User=root
              WorkingDirectory=/opt/authpole
              ExecStart=/opt/authpole/authpole -port=8080 -s3-bucket=${aws_s3_bucket.authpole_storage.id}
              Restart=always
              RestartSec=5
              Environment=AWS_REGION=${var.aws_region}
              Environment=S3_BUCKET=${aws_s3_bucket.authpole_storage.id}

              [Install]
              WantedBy=multi-user.target
              SERVICE

              systemctl daemon-reload
              systemctl enable --now authpole
              echo "Authpole service started successfully!"
              EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "authpole-unikraft-node"
    }
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "authpole_asg" {
  name                = "authpole-asg"
  vpc_zone_identifier = [aws_subnet.public_1.id, aws_subnet.public_2.id]
  target_group_arns   = [aws_lb_target_group.authpole_tg.arn]
  min_size            = 2
  max_size            = 5
  desired_capacity    = 2

  launch_template {
    id      = aws_launch_template.authpole_lt.id
    version = "$Latest"
  }
}
