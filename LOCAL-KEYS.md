# Local security keys

The services now require an RSA signing pair, internal request credential, and session encryption key. These files are intentionally absent from Git. Pulling the projects on a second computer does not provision them automatically.

From the workspace root, using PowerShell 7:

```powershell
./common-security/scripts/provision-local-keys.ps1
```

The script creates only missing files in `.local/security` and preserves existing keys:

- `jwt-private.pem`: RSA PKCS#8 private key for auth (`oauth2`).
- `jwt-public.pem`: matching public key for JWT verification.
- `internal.key`: Base64-encoded 32-byte internal credential.
- `session-encryption.key`: Base64-encoded 32-byte AES key for stored session tokens.

The default key resolver works when the process starts at the workspace root or a direct service directory. For other working directories, set explicit key paths in deployment configuration.

Use these generated keys for this local environment. Sign in again after starting services with a newly generated signing pair. Services participating in the same environment must use matching keys; restoring the existing environment's keys from secure storage is required to keep using its existing signed tokens and encrypted session data. Do not commit or paste private keys or secret file contents into chat. When deploying, mount the private signing key only in auth and provision the production credentials separately.
