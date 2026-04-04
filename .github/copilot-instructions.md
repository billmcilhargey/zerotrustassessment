# Copilot Instructions for Zero Trust Assessment

## Device Code Authentication — CRITICAL

When running `./invoke-ztdev.sh`, `Invoke-ZtDev.ps1`, or any command that triggers Microsoft authentication (Connect-MgGraph, Connect-AzAccount, Connect-ExchangeOnline, etc.):

1. **Run the command as a background terminal process** (`isBackground: true`) so the authentication prompt is not consumed/skipped.
2. **After launching**, check the terminal output for a device code message like:
   - "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ..."
   - "WARNING: To sign in, use a web browser..."
3. **STOP and notify the user** — display the device code URL and code clearly. Tell them to complete the login in their browser.
4. **Wait for the user to confirm** they have completed the login before proceeding with any further commands.
5. **Do NOT run additional terminal commands** until the user confirms authentication is complete.

## Running invoke-ztdev.sh — Default Flags

- Token caching (`-UseTokenCache`) is **enabled by default** — no need to pass it.
- Device code flow (`-UseDeviceCode`) is auto-detected in Codespaces/containers — no need to pass it.
- Example: `./invoke-ztdev.sh -Action RunAll`
- Example: `./invoke-ztdev.sh -Action Connect`
- This is an interactive script. When running it without `-Action`, launch as a **background process** and check output periodically.
- The script has a menu-driven interface. If it is waiting for user input (menu selection, authentication), **pause and ask the user** what to do.
- Never send keystrokes or additional commands to the terminal while the script is waiting for device code authentication.

## General Terminal Rules

- Any command that might prompt for interactive authentication should be run as a background process.
- When you see output containing "devicelogin", "device code", "enter the code", or "authorization_pending", always stop and wait for the user.
