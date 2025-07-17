#!/bin/bash

# Generate JWT RSA key pair for auth1 service

set -e  # Exit on any error

echo "Generating RSA key pair for JWT..."

# Create assets directory if it doesn't exist
mkdir -p assets

# Generate private key (2048 bits) in PKCS1 format
echo "Generating private key..."
openssl genrsa -out assets/private_key.pem 2048

# Generate public key from private key
echo "Generating public key..."
openssl rsa -in assets/private_key.pem -pubout -out assets/public_key.pem

# Set appropriate permissions
chmod 600 assets/private_key.pem
chmod 644 assets/public_key.pem

# Verify the keys were generated correctly
echo "Verifying keys..."
openssl rsa -in assets/private_key.pem -check -noout
openssl rsa -in assets/public_key.pem -pubin -text -noout > /dev/null

echo "✓ RSA key pair generated successfully:"
echo "  Private key: assets/private_key.pem (PKCS1 format)"
echo "  Public key:  assets/public_key.pem"
echo "  Key size:    2048 bits"
