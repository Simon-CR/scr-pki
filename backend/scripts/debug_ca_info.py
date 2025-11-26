import requests
import sys

API_URL = "http://localhost:8000/api/v1"

# Login to get token
def login():
    try:
        response = requests.post(
            f"{API_URL}/auth/login",
            data={"username": "admin", "password": "admin123"}
        )
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception as e:
        print(f"Login failed: {e}")
        if hasattr(e, 'response') and e.response:
            print(e.response.text)
        sys.exit(1)

def check_ca_info(token):
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{API_URL}/ca/info", headers=headers)
        print(f"Status Code: {response.status_code}")
        print(response.text)
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    token = login()
    check_ca_info(token)
