# Database Migrations

This directory contains database migrations for the auth1 service using Bun's migration system.

## Features

- **Up/Down migrations**: Each migration has both forward and rollback capabilities
- **Transaction support**: Migrations run in transactions for atomicity
- **Seed data**: Initial data seeding capability
- **CLI management**: Easy-to-use command-line interface
- **Status tracking**: View migration status and history

## Directory Structure

```
migrations/
├── README.md              # This file
├── main.go               # CLI tool for migration management
├── migrations.go         # Migration definitions
└── go.mod               # Go module file
```

## Usage

### Using the CLI Tool

Navigate to the migrations directory and use the Go CLI tool:

```bash
# Initialize migration tracking table
go run . init

# Run pending migrations
go run . up

# Check migration status
go run . status

# Rollback last migration group
go run . down

# Reset database (rollback all migrations)
go run . reset

# Create new migration
go run . create migration_name
```

### Using the Shell Script

From the project root directory:

```bash
# Initialize migrations
./scripts/migrate.sh init

# Run migrations
./scripts/migrate.sh up

# Check status
./scripts/migrate.sh status

# Rollback last migration
./scripts/migrate.sh down

# Create new migration
./scripts/migrate.sh create add_new_table

# With specific environment
./scripts/migrate.sh -e production up
```

## Current Migrations

### 1. `20240101000001_init_users_table`
- Creates the main `users` table
- Adds PostgreSQL trigger for automatic `updated_at` timestamps
- **Up**: Creates table with all columns and trigger
- **Down**: Drops table, trigger, and trigger function

### 2. `20240101000002_add_user_indexes`
- Adds performance indexes to the users table
- **Up**: Creates indexes on email, phone, created_at, etc.
- **Down**: Drops all indexes

### 3. `20240101000003_seed_initial_data`
- Adds initial seed data for development/testing
- **Up**: Inserts admin user with email `admin@auth1.dev`
- **Down**: Removes seed data

## Migration Best Practices

### Writing Migrations

1. **Make migrations atomic**: Each migration should be a single, cohesive change
2. **Test rollbacks**: Always test both up and down migrations
3. **Use transactions**: The system automatically wraps migrations in transactions
4. **Handle errors**: Return meaningful error messages
5. **Add comments**: Document complex migrations

### Adding New Migrations

1. Create a new migration using the CLI:
   ```bash
   go run . create add_user_roles_table
   ```

2. Edit the generated migration file to implement your schema changes

3. Add the migration to `migrations.go`:
   ```go
   func init() {
       // ... existing migrations
       Migrations.MustRegister(addUserRolesTableUp, addUserRolesTableDown)
   }
   ```

4. Test the migration:
   ```bash
   go run . up
   go run . status
   ```

### Migration Naming Convention

Use descriptive names with timestamps:
- `20240101000001_init_users_table`
- `20240101000002_add_user_indexes`
- `20240101000003_seed_initial_data`

## Environment Configuration

The migration system reads configuration from:

1. **Config file**: `config.yaml` in the project root
2. **Environment variables**: 
   - `DATABASE_HOST`
   - `DATABASE_PORT`
   - `DATABASE_USER`
   - `DATABASE_PASSWORD`
   - `DATABASE_NAME`
   - `DATABASE_SSL_MODE`

## Docker Integration

The `docker-compose.yml` includes a migration service that automatically runs migrations when the stack starts:

```yaml
migrations:
  build: .
  depends_on:
    postgres:
      condition: service_healthy
  command: ["sh", "-c", "cd migrations && go run . init && go run . up"]
  restart: "no"
```

## Troubleshooting

### Common Issues

1. **Connection refused**: Ensure PostgreSQL is running
2. **Config not found**: Check that `config.yaml` exists in project root
3. **Permission denied**: Make sure `scripts/migrate.sh` is executable
4. **Migration fails**: Check database logs and migration error messages

### Debugging

1. Enable debug logging:
   ```bash
   BUNDEBUG=1 go run . up
   ```

2. Check migration status:
   ```bash
   go run . status
   ```

3. View database migration table:
   ```sql
   SELECT * FROM bun_migrations ORDER BY id DESC;
   ```

## Production Deployment

For production deployments:

1. **Run migrations before deploying the application**
2. **Use environment-specific configuration**
3. **Take database backups before major migrations**
4. **Test migrations in staging environment first**

Example production migration:
```bash
./scripts/migrate.sh -e production up
```

## Development Workflow

1. **Create migration**: `./scripts/migrate.sh create feature_name`
2. **Run migration**: `./scripts/migrate.sh up`
3. **Test rollback**: `./scripts/migrate.sh down`
4. **Check status**: `./scripts/migrate.sh status`
5. **Commit changes**: Git commit both migration code and any related changes

## Notes

- Migrations are run in timestamp order
- Each migration group gets a unique ID
- Failed migrations prevent subsequent migrations from running
- The system tracks which migrations have been applied
- Rollbacks work on migration groups, not individual migrations 