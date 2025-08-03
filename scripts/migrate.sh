#!/bin/bash

# Script for database migration management using Bun migration system
# Usage: ./scripts/migrate.sh [command] [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENVIRONMENT="development"
MIGRATION_DIR="migrations"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  init                 Initialize migration tracking table"
    echo "  up                   Run pending migrations"
    echo "  down                 Rollback the last migration group"
    echo "  status               Show migration status"
    echo "  reset                Reset database (rollback all migrations)"
    echo "  create [name]        Create a new migration file"
    echo "  seed                 Run environment-specific seed data"
    echo "  deploy               Run init, up, and seed in sequence (production-ready)"
    echo ""
    echo "Options:"
    echo "  -e, --env [env]      Set environment (default: development)"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 init"
    echo "  $0 up"
    echo "  $0 down"
    echo "  $0 status"
    echo "  $0 seed"
    echo "  $0 deploy"
    echo "  $0 create add_users_table"
    echo "  $0 -e production deploy"
    echo "  $0 -e staging seed"
}

# Function to check if migration directory exists
check_migration_dir() {
    if [ ! -d "$MIGRATION_DIR" ]; then
        print_error "Migration directory '$MIGRATION_DIR' not found!"
        print_info "Please run this script from the project root directory."
        exit 1
    fi
}

# Function to check if config file exists
check_config() {
    if [ ! -f "config.yaml" ] && [ ! -f "config.yml" ]; then
        print_warning "No config.yaml or config.yml found. Using environment variables."
        print_info "Make sure database connection environment variables are set:"
        print_info "  DATABASE_HOST, DATABASE_PORT, DATABASE_USER, DATABASE_PASSWORD, DATABASE_NAME"
    fi
}

# Function to validate environment
validate_environment() {
    case "$ENVIRONMENT" in
        development|dev|staging|production|prod|test)
            return 0
            ;;
        *)
            print_warning "Unknown environment: $ENVIRONMENT"
            print_info "Valid environments: development, staging, production, test"
            return 1
            ;;
    esac
}

# Function to run migration command
run_migration() {
    local command="$1"
    local migration_name="$2"
    
    check_migration_dir
    check_config
    validate_environment
    
    print_info "Running migration command: $command"
    print_info "Environment: $ENVIRONMENT"
    
    # Add safety check for production environment
    if [ "$ENVIRONMENT" = "production" ] || [ "$ENVIRONMENT" = "prod" ]; then
        if [ "$command" = "reset" ] || [ "$command" = "down" ]; then
            print_error "Dangerous operation '$command' is not allowed in production environment"
            print_info "Please use a different environment or contact system administrator"
            exit 1
        fi
    fi
    
    case "$command" in
        "init")
            print_info "Initializing migration tracking table..."
            (cd "$MIGRATION_DIR" && go run . init)
            print_success "Migration tracking table initialized"
            ;;
        "up")
            print_info "Running pending migrations..."
            (cd "$MIGRATION_DIR" && go run . up)
            print_success "Migrations completed"
            ;;
        "down")
            print_warning "Rolling back last migration group..."
            (cd "$MIGRATION_DIR" && go run . down)
            print_success "Rollback completed"
            ;;
        "status")
            print_info "Checking migration status..."
            (cd "$MIGRATION_DIR" && go run . status)
            ;;
        "reset")
            print_warning "This will reset the database (rollback all migrations)!"
            read -p "Are you sure? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                print_info "Resetting database..."
                (cd "$MIGRATION_DIR" && go run . reset)
                print_success "Database reset completed"
            else
                print_info "Reset cancelled"
            fi
            ;;
        "create")
            if [ -z "$migration_name" ]; then
                print_error "Migration name is required for create command"
                exit 1
            fi
            print_info "Creating migration: $migration_name"
            (cd "$MIGRATION_DIR" && go run . create "$migration_name")
            print_success "Migration file created"
            ;;
        "seed")
            print_info "Running environment-specific seed data..."
            print_info "Environment: $ENVIRONMENT"
            (cd "$MIGRATION_DIR" && go run . seed)
            print_success "Seed data completed"
            ;;
        "deploy")
            print_info "Running production deployment sequence..."
            print_info "Environment: $ENVIRONMENT"
            
            # Step 1: Initialize
            print_info "Step 1/3: Initializing migration tracking..."
            (cd "$MIGRATION_DIR" && go run . init)
            print_success "Migration tracking initialized"
            
            # Step 2: Run migrations
            print_info "Step 2/3: Running pending migrations..."
            (cd "$MIGRATION_DIR" && go run . up)
            print_success "Migrations completed"
            
            # Step 3: Seed data (only for non-production environments)
            if [ "$ENVIRONMENT" != "production" ] && [ "$ENVIRONMENT" != "prod" ]; then
                print_info "Step 3/3: Running seed data for $ENVIRONMENT environment..."
                (cd "$MIGRATION_DIR" && go run . seed)
                print_success "Seed data completed"
            else
                print_info "Step 3/3: Skipping seed data for production environment"
            fi
            
            print_success "Deployment sequence completed successfully"
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--env)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        init|up|down|status|reset|create|seed|deploy)
            COMMAND="$1"
            if [ "$1" = "create" ] && [ -n "$2" ] && [[ ! "$2" =~ ^- ]]; then
                MIGRATION_NAME="$2"
                shift 2
            else
                shift
            fi
            ;;
        *)
            if [ -z "$COMMAND" ]; then
                print_error "Unknown option: $1"
                show_usage
                exit 1
            else
                MIGRATION_NAME="$1"
                shift
            fi
            ;;
    esac
done

# Check if command is provided
if [ -z "$COMMAND" ]; then
    print_error "No command provided"
    show_usage
    exit 1
fi

# Export environment variable for Go application
export APP_ENVIRONMENT="$ENVIRONMENT"

# Run the migration command
run_migration "$COMMAND" "$MIGRATION_NAME" 