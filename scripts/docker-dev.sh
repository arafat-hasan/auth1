#!/bin/bash
# Development Docker Quick Start Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "🚀 Auth Service - Development Environment"
echo "=========================================="
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check dependencies
echo "📋 Checking dependencies..."
if ! command_exists docker; then
    echo "❌ Error: Docker is not installed"
    echo "   Install from: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command_exists docker-compose; then
    echo "❌ Error: Docker Compose is not installed"
    echo "   Install from: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker and Docker Compose are installed"
echo ""

# Parse command
COMMAND=${1:-up}

case "$COMMAND" in
    up|start)
        echo "🔧 Starting development environment..."
        docker-compose up -d
        echo ""
        echo "⏳ Waiting for services to be healthy..."
        sleep 5

        echo ""
        echo "✅ Services are starting!"
        echo ""
        echo "📍 Access Points:"
        echo "   Auth Service:     http://localhost:8080"
        echo "   Auth Service API: http://localhost:8080/api/v1"
        echo "   Swagger Docs:     http://localhost:8080/swagger/index.html"
        echo "   Redis Insight:    http://localhost:5540"
        echo "   RabbitMQ Mgmt:    http://localhost:15672 (guest/guest)"
        echo ""
        echo "🔍 Useful Commands:"
        echo "   View logs:        docker-compose logs -f"
        echo "   View auth logs:   docker-compose logs -f auth-service"
        echo "   View Redis keys:  docker-compose exec redis redis-cli KEYS '*'"
        echo "   Stop services:    docker-compose down"
        echo ""
        echo "📊 Check service status:"
        docker-compose ps
        ;;

    down|stop)
        echo "🛑 Stopping development environment..."
        docker-compose down
        echo "✅ Services stopped"
        ;;

    restart)
        echo "♻️  Restarting development environment..."
        docker-compose restart
        echo "✅ Services restarted"
        ;;

    logs)
        echo "📜 Viewing logs (Ctrl+C to exit)..."
        docker-compose logs -f "${2:-auth-service}"
        ;;

    ps|status)
        echo "📊 Service Status:"
        docker-compose ps
        ;;

    redis)
        echo "🔴 Connecting to Redis CLI..."
        docker-compose exec redis redis-cli
        ;;

    db|psql)
        echo "🐘 Connecting to PostgreSQL..."
        docker-compose exec postgres psql -U auth1 -d auth1
        ;;

    clean)
        echo "🧹 Cleaning up (removes volumes - WARNING: deletes all data!)..."
        read -p "Are you sure? This will delete all data! (yes/no): " -r
        echo
        if [[ $REPLY == "yes" ]]; then
            docker-compose down -v
            echo "✅ All data cleaned"
        else
            echo "❌ Aborted"
        fi
        ;;

    rebuild)
        echo "🔨 Rebuilding services..."
        docker-compose build --no-cache
        docker-compose up -d
        echo "✅ Services rebuilt"
        ;;

    test)
        echo "🧪 Running tests..."
        echo ""
        echo "1. Testing Auth Service health..."
        if curl -s -f http://localhost:8080/health > /dev/null; then
            echo "   ✅ Auth Service is healthy"
        else
            echo "   ❌ Auth Service is not responding"
        fi

        echo ""
        echo "2. Testing Redis..."
        if docker-compose exec -T redis redis-cli ping | grep -q PONG; then
            echo "   ✅ Redis is working"
        else
            echo "   ❌ Redis is not responding"
        fi

        echo ""
        echo "3. Testing PostgreSQL..."
        if docker-compose exec -T postgres psql -U auth1 -d auth1 -c "SELECT 1" > /dev/null 2>&1; then
            echo "   ✅ PostgreSQL is working"
        else
            echo "   ❌ PostgreSQL is not responding"
        fi

        echo ""
        echo "4. Checking Redis keys..."
        KEY_COUNT=$(docker-compose exec -T redis redis-cli DBSIZE | grep -oE '[0-9]+')
        echo "   📊 Redis has $KEY_COUNT keys"

        echo ""
        echo "5. Sample Redis keys:"
        docker-compose exec redis redis-cli --scan --pattern '*' | head -10
        ;;

    help|--help|-h)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  up, start    Start development environment (default)"
        echo "  down, stop   Stop development environment"
        echo "  restart      Restart all services"
        echo "  logs [svc]   View logs (default: auth-service)"
        echo "  ps, status   Show service status"
        echo "  redis        Connect to Redis CLI"
        echo "  db, psql     Connect to PostgreSQL"
        echo "  clean        Stop and remove all data (⚠️  destructive)"
        echo "  rebuild      Rebuild and restart services"
        echo "  test         Run basic health checks"
        echo "  help         Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0                    # Start services"
        echo "  $0 logs               # View auth-service logs"
        echo "  $0 logs redis         # View Redis logs"
        echo "  $0 redis              # Open Redis CLI"
        echo "  $0 test               # Run health checks"
        ;;

    *)
        echo "❌ Unknown command: $COMMAND"
        echo "   Run '$0 help' for usage"
        exit 1
        ;;
esac
