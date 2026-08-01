terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "Authpole"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# VPC and Network Infrastructure
resource "aws_vpc" "authpole_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "authpole-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.authpole_vpc.id

  tags = {
    Name = "authpole-igw"
  }
}

resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.authpole_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "authpole-public-1"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.authpole_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "authpole-public-2"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.authpole_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "authpole-public-rt"
  }
}

resource "aws_route_table_association" "public_1_assoc" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_2_assoc" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public_rt.id
}
