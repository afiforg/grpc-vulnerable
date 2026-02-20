package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	pb "grpc-vulnerable/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	JWT_SECRET = "secret-key-change-in-production"
	PORT       = 50051
)

// User represents a user in the system
type User struct {
	ID          int32
	Username    string
	Email       string
	Role        string
	PasswordHash string
	APIKey      string
	CreatedAt   string
}

// JWT Claims structure
type Claims struct {
	UserID   int32  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	Exp      int64  `json:"exp"`
}

// Sample users database
var users = map[string]User{
	"alice": {
		ID:           1,
		Username:     "alice",
		Email:        "alice@example.com",
		Role:         "user",
		PasswordHash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // sha256 of "alice123"
		APIKey:       "alice_api_key_12345",
		CreatedAt:    "2024-01-01T00:00:00Z",
	},
	"bob": {
		ID:           2,
		Username:     "bob",
		Email:        "bob@example.com",
		Role:         "user",
		PasswordHash: "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f", // sha256 of "bob123"
		APIKey:       "bob_api_key_67890",
		CreatedAt:    "2024-01-02T00:00:00Z",
	},
	"admin": {
		ID:           3,
		Username:     "admin",
		Email:        "admin@example.com",
		Role:         "admin",
		PasswordHash: "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9", // sha256 of "admin123"
		APIKey:       "admin_api_key_secret",
		CreatedAt:    "2024-01-01T00:00:00Z",
	},
}

// Simple password storage (in production, use bcrypt)
var passwords = map[string]string{
	"alice": "alice123",
	"bob":   "bob123",
	"admin": "admin123",
}

// Generate JWT token
func generateJWT(user User) string {
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	claims := Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Exp:      time.Now().Add(24 * time.Hour).Unix(),
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	message := headerB64 + "." + claimsB64
	mac := hmac.New(sha256.New, []byte(JWT_SECRET))
	mac.Write([]byte(message))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return message + "." + signature
}

// Verify JWT token
func verifyJWT(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(JWT_SECRET))
	mac.Write([]byte(message))
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if parts[2] != expectedSignature {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, err
	}

	// Check expiration
	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	return &claims, nil
}

// Extract token from gRPC metadata
func extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	tokens := md.Get("authorization")
	if len(tokens) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "missing authorization header")
	}

	token := tokens[0]
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	return token, nil
}

// Authenticate user from context
func authenticate(ctx context.Context) (*Claims, error) {
	token, err := extractToken(ctx)
	if err != nil {
		return nil, err
	}

	claims, err := verifyJWT(token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
	}

	return claims, nil
}

// VULNERABLE: Check if user is admin - but doesn't actually check!
func requireAdmin(ctx context.Context) (*Claims, error) {
	claims, err := authenticate(ctx)
	if err != nil {
		return nil, err
	}

	// VULNERABLE: Missing role check!
	// Should check: if claims.Role != "admin", return error
	// But it doesn't check the role at all

	log.Printf("User %s (role: %s) accessing admin endpoint", claims.Username, claims.Role)

	return claims, nil
}

// UserService implements the gRPC service
type UserService struct {
	pb.UnimplementedUserServiceServer
}

// Login - Authentication works correctly
func (s *UserService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	user, exists := users[req.Username]
	if !exists {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	password, exists := passwords[req.Username]
	if !exists || password != req.Password {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	token := generateJWT(user)

	return &pb.LoginResponse{
		Token: token,
		User: &pb.UserProfile{
			UserId:   user.ID,
			Username: user.Username,
			Email:    user.Email,
			Role:     user.Role,
		},
	}, nil
}

// GetUserProfile - Requires authentication, works correctly
func (s *UserService) GetUserProfile(ctx context.Context, req *pb.GetUserProfileRequest) (*pb.UserProfile, error) {
	claims, err := authenticate(ctx)
	if err != nil {
		return nil, err
	}

	// Find user by ID from claims
	var user *User
	for _, u := range users {
		if u.ID == claims.UserID {
			user = &u
			break
		}
	}

	if user == nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	return &pb.UserProfile{
		UserId:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Role:     user.Role,
	}, nil
}

// ListAllUsers - VULNERABLE: Should require admin role but doesn't check
func (s *UserService) ListAllUsers(ctx context.Context, req *pb.ListAllUsersRequest) (*pb.ListAllUsersResponse, error) {
	// VULNERABLE: Uses requireAdmin which doesn't actually check the role
	claims, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("User %s (role: %s) listing all users", claims.Username, claims.Role)

	userList := make([]*pb.UserProfile, 0, len(users))
	for _, user := range users {
		userList = append(userList, &pb.UserProfile{
			UserId:   user.ID,
			Username: user.Username,
			Email:    user.Email,
			Role:     user.Role,
		})
	}

	return &pb.ListAllUsersResponse{
		Users: userList,
	}, nil
}

// DeleteUser - VULNERABLE: Should require admin role but doesn't check
func (s *UserService) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	// VULNERABLE: Uses requireAdmin which doesn't actually check the role
	claims, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("User %s (role: %s) deleting user %d", claims.Username, claims.Role, req.UserId)

	return &pb.DeleteUserResponse{
		Success: true,
		Message: fmt.Sprintf("User %d deleted by %s", req.UserId, claims.Username),
	}, nil
}

// UpdateSystemSettings - VULNERABLE: Should require admin role but doesn't check
func (s *UserService) UpdateSystemSettings(ctx context.Context, req *pb.UpdateSystemSettingsRequest) (*pb.UpdateSystemSettingsResponse, error) {
	// VULNERABLE: Uses requireAdmin which doesn't actually check the role
	claims, err := requireAdmin(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("User %s (role: %s) updating system setting %s to %s", claims.Username, claims.Role, req.Setting, req.Value)

	return &pb.UpdateSystemSettingsResponse{
		Success: true,
		Message: fmt.Sprintf("Setting '%s' updated to '%s' by %s", req.Setting, req.Value, claims.Username),
	}, nil
}

// UpdateUserSettings - VULNERABLE: Missing ownership check
func (s *UserService) UpdateUserSettings(ctx context.Context, req *pb.UpdateUserSettingsRequest) (*pb.UpdateUserSettingsResponse, error) {
	claims, err := authenticate(ctx)
	if err != nil {
		return nil, err
	}

	// VULNERABLE: Should check if claims.UserID == req.TargetUserId or claims.Role == "admin"
	// But it doesn't check either condition

	log.Printf("User %d updating settings for user %d", claims.UserID, req.TargetUserId)

	return &pb.UpdateUserSettingsResponse{
		Success: true,
		Message: fmt.Sprintf("Settings for user %d updated by user %d", req.TargetUserId, claims.UserID),
	}, nil
}

// ModerateContent - VULNERABLE: Missing role check
func (s *UserService) ModerateContent(ctx context.Context, req *pb.ModerateContentRequest) (*pb.ModerateContentResponse, error) {
	claims, err := authenticate(ctx)
	if err != nil {
		return nil, err
	}

	// VULNERABLE: Should check if role is "moderator" or "admin"
	// But it only checks if user is authenticated, not their role

	log.Printf("User %s (role: %s) moderating content %s", claims.Username, claims.Role, req.ContentId)

	return &pb.ModerateContentResponse{
		Success: true,
		Message: fmt.Sprintf("Content %s moderated by %s (role: %s)", req.ContentId, claims.Username, claims.Role),
	}, nil
}

// GetUserDetails - VULNERABLE: Information disclosure
func (s *UserService) GetUserDetails(ctx context.Context, req *pb.GetUserDetailsRequest) (*pb.UserDetails, error) {
	claims, err := authenticate(ctx)
	if err != nil {
		return nil, err
	}

	// VULNERABLE: Should check if claims.UserID == req.UserId or claims.Role == "admin"
	// But it doesn't check ownership

	// VULNERABLE: Exposes sensitive information like password hash and API key
	// These should never be returned in API responses
	var user *User
	for _, u := range users {
		if u.ID == req.UserId {
			user = &u
			break
		}
	}

	if user == nil {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	log.Printf("User %d accessing details for user %d", claims.UserID, req.UserId)

	return &pb.UserDetails{
		UserId:       user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Role:         user.Role,
		PasswordHash: user.PasswordHash, // VULNERABLE: Should not expose
		ApiKey:       user.APIKey,        // VULNERABLE: Should not expose
		CreatedAt:    user.CreatedAt,
	}, nil
}

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", PORT))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterUserServiceServer(s, &UserService{})

	fmt.Printf("Vulnerable gRPC Server starting on port %d\n", PORT)
	fmt.Println("Sample users:")
	fmt.Println("  - alice / alice123 (role: user)")
	fmt.Println("  - bob / bob123 (role: user)")
	fmt.Println("  - admin / admin123 (role: admin)")
	fmt.Println("\nVULNERABILITIES:")
	fmt.Println("  - Regular users can access admin endpoints")
	fmt.Println("  - Users can modify other users' settings")
	fmt.Println("  - Sensitive information (password hash, API key) exposed")
	fmt.Println("  - Missing authorization checks")

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
