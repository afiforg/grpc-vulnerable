# Vulnerable gRPC Service (Go)

This is an intentionally vulnerable gRPC service designed for testing security scanners. **DO NOT USE IN PRODUCTION.**

## Vulnerability: Flawed Authorization in gRPC Service

This application demonstrates **authorization vulnerabilities** in a gRPC service where:
- **Authentication works correctly** - users can log in and receive JWT tokens
- **Authorization is flawed** - authorization checks are missing or insufficient, allowing users to access resources or perform actions beyond their permissions
- **Information disclosure** - sensitive data like password hashes and API keys are exposed

## Vulnerabilities

### 1. **ListAllUsers** - Missing Admin Role Check
- **Expected**: Only users with "admin" role should access this endpoint
- **Actual**: Any authenticated user can access it
- **Vulnerability**: The `requireAdmin()` function checks authentication but doesn't verify the role is "admin"
- **Impact**: Regular users can enumerate all users in the system

### 2. **DeleteUser** - Missing Admin Authorization
- **Expected**: Only admins should be able to delete users
- **Actual**: Any authenticated user can delete users
- **Vulnerability**: No role verification before allowing user deletion
- **Impact**: Regular users can delete other users, including admins

### 3. **UpdateSystemSettings** - Missing Admin Authorization
- **Expected**: Only admins should be able to update system settings
- **Actual**: Any authenticated user can modify system settings
- **Vulnerability**: Authorization check is missing
- **Impact**: Regular users can change critical system configuration

### 4. **UpdateUserSettings** - Missing Ownership Check
- **Expected**: Users should only be able to update their own settings, or admins can update any user's settings
- **Actual**: Any authenticated user can update any user's settings
- **Vulnerability**: No check to verify `currentUserID == targetUserID` or `currentUser.role == "admin"`
- **Impact**: Users can modify other users' settings without authorization

### 5. **ModerateContent** - Missing Moderator Role Check
- **Expected**: Only users with "moderator" or "admin" role should moderate content
- **Actual**: Any authenticated user can moderate content
- **Vulnerability**: Endpoint checks if user is authenticated but doesn't verify role
- **Impact**: Regular users can perform moderation actions

### 6. **GetUserDetails** - Information Disclosure
- **Expected**: Should only return non-sensitive user information
- **Actual**: Returns password hashes and API keys
- **Vulnerability**: Exposes sensitive information that should never be returned
- **Impact**: Attackers can obtain password hashes and API keys

## Sample Users

The application includes sample users:

- **alice** / alice123 (role: user, user_id: 1)
- **bob** / bob123 (role: user, user_id: 2)
- **admin** / admin123 (role: admin, user_id: 3)

## Setup

### Prerequisites

1. Install Go (1.21 or later)
2. Install Protocol Buffers compiler:
   ```bash
   # macOS
   brew install protobuf
   
   # Linux
   sudo apt-get install protobuf-compiler
   ```

3. Install Go protobuf plugins:
   ```bash
   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
   ```

### Build and Run

1. Install dependencies:
   ```bash
   cd grpc-vulnerable
   make install-deps
   go mod download
   ```

2. Generate protobuf code:
   ```bash
   make proto
   ```

3. Build the server:
   ```bash
   make build
   ```

4. Run the server:
   ```bash
   make run
   # Or directly:
   go run main.go
   ```

The server will start on `localhost:50051`

## Testing with gRPC Client

### Using Python gRPC Client

Install Python gRPC tools:
```bash
pip install grpcio grpcio-tools
```

Generate Python stubs:
```bash
python -m grpc_tools.protoc -I./proto --python_out=. --grpc_python_out=. proto/user_service.proto
```

### Using Go Client

See `poc.go` for a Go-based proof of concept client.

### Using grpcurl (Command Line)

Install grpcurl:
```bash
# macOS
brew install grpcurl

# Linux
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

Test the service:
```bash
# List services
grpcurl -plaintext localhost:50051 list

# Call Login
grpcurl -plaintext -d '{"username":"alice","password":"alice123"}' \
  localhost:50051 user_service.UserService/Login

# Call ListAllUsers (requires token in metadata)
# First get token from login, then:
grpcurl -plaintext -H "authorization: Bearer <TOKEN>" \
  localhost:50051 user_service.UserService/ListAllUsers
```

## Testing Vulnerabilities

### Test 1: Regular User Accessing Admin Endpoint

```bash
# 1. Login as regular user (alice)
# 2. Use the token to call ListAllUsers
# Expected: Should fail with permission denied
# Actual: Succeeds - VULNERABILITY CONFIRMED
```

### Test 2: Regular User Deleting Users

```bash
# 1. Login as regular user (bob)
# 2. Use the token to call DeleteUser with another user's ID
# Expected: Should fail with permission denied
# Actual: Succeeds - VULNERABILITY CONFIRMED
```

### Test 3: Regular User Updating System Settings

```bash
# 1. Login as regular user (alice)
# 2. Use the token to call UpdateSystemSettings
# Expected: Should fail with permission denied
# Actual: Succeeds - VULNERABILITY CONFIRMED
```

### Test 4: User Modifying Other User's Settings

```bash
# 1. Login as alice (user_id=1)
# 2. Use the token to call UpdateUserSettings with target_user_id=2
# Expected: Should fail with permission denied
# Actual: Succeeds - VULNERABILITY CONFIRMED
```

### Test 5: Regular User Moderating Content

```bash
# 1. Login as regular user (bob)
# 2. Use the token to call ModerateContent
# Expected: Should fail with permission denied
# Actual: Succeeds - VULNERABILITY CONFIRMED
```

### Test 6: Information Disclosure

```bash
# 1. Login as any user
# 2. Use the token to call GetUserDetails for any user
# Expected: Should only return non-sensitive information
# Actual: Returns password hash and API key - VULNERABILITY CONFIRMED
```

## Purpose

This code is intentionally vulnerable for security testing purposes only. A security scanner should detect:

- Missing authorization checks in gRPC services
- Insufficient role-based access control (RBAC)
- Missing ownership verification
- Privilege escalation vulnerabilities
- Information disclosure vulnerabilities
- Horizontal privilege escalation (user accessing other user's resources)
- Vertical privilege escalation (regular user accessing admin functions)

## Security Best Practices (NOT implemented here)

- **Implement proper authorization checks**: Always verify user roles and permissions before allowing access
- **Use role-based access control (RBAC)**: Enforce role checks in gRPC interceptors/middleware
- **Verify ownership**: Check if user owns the resource or has admin privileges before allowing modifications
- **Principle of least privilege**: Users should only have access to resources they need
- **Defense in depth**: Check authorization at multiple layers (interceptor, handler, database)
- **Fail securely**: Default to denying access if authorization cannot be verified
- **Log authorization failures**: Monitor and log unauthorized access attempts
- **Use gRPC interceptors**: Implement authorization checks in gRPC interceptors for consistent enforcement
- **Never expose sensitive data**: Password hashes, API keys, and other secrets should never be returned in API responses
- **Use proper error messages**: Don't leak information about resource existence in error messages

## How to Fix

### Fix 1: Add Role Check in requireAdmin

```go
func requireAdmin(ctx context.Context) (*Claims, error) {
    claims, err := authenticate(ctx)
    if err != nil {
        return nil, err
    }

    // FIX: Actually check the role
    if claims.Role != "admin" {
        return nil, status.Errorf(codes.PermissionDenied, "admin access required")
    }

    return claims, nil
}
```

### Fix 2: Add Ownership Check

```go
func (s *UserService) UpdateUserSettings(ctx context.Context, req *pb.UpdateUserSettingsRequest) (*pb.UpdateUserSettingsResponse, error) {
    claims, err := authenticate(ctx)
    if err != nil {
        return nil, err
    }

    // FIX: Check ownership or admin role
    if claims.UserID != req.TargetUserId && claims.Role != "admin" {
        return nil, status.Errorf(codes.PermissionDenied, "access denied")
    }

    // ... rest of handler
}
```

### Fix 3: Remove Sensitive Data from Responses

```go
func (s *UserService) GetUserDetails(ctx context.Context, req *pb.GetUserDetailsRequest) (*pb.UserDetails, error) {
    claims, err := authenticate(ctx)
    if err != nil {
        return nil, err
    }

    // FIX: Check ownership or admin role
    if claims.UserID != req.UserId && claims.Role != "admin" {
        return nil, status.Errorf(codes.PermissionDenied, "access denied")
    }

    // ... get user ...

    // FIX: Don't expose sensitive information
    return &pb.UserDetails{
        UserId:    user.ID,
        Username:  user.Username,
        Email:     user.Email,
        Role:      user.Role,
        CreatedAt: user.CreatedAt,
        // PasswordHash and ApiKey should NOT be included
    }, nil
}
```

### Fix 4: Use gRPC Interceptors for Authorization

```go
func adminInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
    // Check if this is an admin endpoint
    if strings.Contains(info.FullMethod, "Admin") {
        claims, err := authenticate(ctx)
        if err != nil {
            return nil, err
        }
        if claims.Role != "admin" {
            return nil, status.Errorf(codes.PermissionDenied, "admin access required")
        }
    }
    return handler(ctx, req)
}

// In main():
s := grpc.NewServer(
    grpc.UnaryInterceptor(adminInterceptor),
)
```
