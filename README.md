# HashiCorp Vault - Utilities

These functions were written to work with secrets stored on the vault server.  Vault on windows is cumbersome to use and has me wasting time trying to provide the specific input that vault.exe is expecting.  Additionally, vault.exe writes your token to a file saved on disk with the default TTL defaulted to 32 days.

Using utilities here, vault_token is saved to a global variable which can be used within child scopes but disappears after you close the powershell host.  Use these functions to read, write, delete and update your secrets via web calls to your vault server.
