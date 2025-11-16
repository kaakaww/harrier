# Harrier Proxy Setup Guide

This guide explains how to set up and use the Harrier MITM proxy to capture HTTP/HTTPS traffic as HAR files.

## Quick Start

```bash
# Start the proxy (generates CA certificate on first run)
harrier proxy

# Configure your browser to use localhost:8080 as HTTP/HTTPS proxy
# Browse normally
# Press Ctrl+C to stop and save HAR file
```

## CA Certificate Installation

To intercept HTTPS traffic, you must install Harrier's CA certificate in your system's trust store. Without this, browsers will show security warnings for HTTPS sites.

The CA certificate is generated automatically on first run and saved to:
- **Certificate:** `~/.harrier/ca.crt`
- **Private Key:** `~/.harrier/ca.key`

**Security Note:** Keep the private key (`ca.key`) secure. Anyone with this file can impersonate any HTTPS website to your system.

---

## macOS Installation

### System-Wide (Recommended)

1. Start the proxy to generate the certificate:
   ```bash
   harrier proxy
   ```

2. Press `Ctrl+C` to stop it (you just need the certificate generated)

3. Open **Keychain Access**:
   - Applications → Utilities → Keychain Access
   - Or use Spotlight: `Cmd+Space`, type "Keychain Access"

4. Import the certificate:
   - File → Import Items...
   - Navigate to `~/.harrier/ca.crt`
   - Select "login" or "System" keychain
   - Click "Open"

5. Trust the certificate:
   - Find "Harrier MITM Proxy CA" in the keychain
   - Double-click it to open details
   - Expand "Trust" section
   - Set "When using this certificate" to **"Always Trust"**
   - Close the window (you'll need to enter your password)

6. Restart your browser for changes to take effect

### Verification

```bash
# Check if certificate is trusted
security verify-cert -c ~/.harrier/ca.crt
```

### Chrome/Chromium on macOS

Chrome should automatically use the system keychain. If you still see warnings:

1. Go to `chrome://settings/certificates`
2. Navigate to "Authorities" tab
3. Click "Import"
4. Select `~/.harrier/ca.crt`
5. Check "Trust this certificate for identifying websites"
6. Click "OK"

---

## Linux Installation

### System-Wide (Ubuntu/Debian)

1. Generate the certificate:
   ```bash
   harrier proxy
   # Press Ctrl+C immediately
   ```

2. Copy certificate to system trust store:
   ```bash
   sudo cp ~/.harrier/ca.crt /usr/local/share/ca-certificates/harrier-ca.crt
   ```

3. Update certificate store:
   ```bash
   sudo update-ca-certificates
   ```

4. Restart your browser

### Fedora/RHEL/CentOS

```bash
sudo cp ~/.harrier/ca.crt /etc/pki/ca-trust/source/anchors/harrier-ca.crt
sudo update-ca-trust
```

### Arch Linux

```bash
sudo cp ~/.harrier/ca.crt /etc/ca-certificates/trust-source/anchors/harrier-ca.crt
sudo trust extract-compat
```

### Firefox (Linux)

Firefox uses its own certificate store:

1. Open Firefox preferences: `about:preferences#privacy`
2. Scroll to "Certificates" section
3. Click "View Certificates"
4. Go to "Authorities" tab
5. Click "Import..."
6. Select `~/.harrier/ca.crt`
7. Check "Trust this CA to identify websites"
8. Click "OK"

### Chrome/Chromium (Linux)

1. Go to `chrome://settings/certificates`
2. Click "Authorities" tab
3. Click "Import"
4. Select `~/.harrier/ca.crt`
5. Check "Trust this certificate for identifying websites"
6. Click "OK"

---

## Windows Installation

### System-Wide

1. Generate the certificate:
   ```powershell
   harrier proxy
   # Press Ctrl+C immediately
   ```

2. Open **Certificate Manager**:
   - Press `Win+R`
   - Type `certmgr.msc`
   - Press Enter

3. Import the certificate:
   - Expand "Trusted Root Certification Authorities"
   - Right-click "Certificates"
   - Select "All Tasks" → "Import..."
   - Click "Next"
   - Browse to `C:\Users\YourUsername\.harrier\ca.crt`
   - Click "Next", then "Finish"

4. Restart your browser

### Alternative: Command Line (PowerShell as Administrator)

```powershell
certutil -addstore -user Root "$env:USERPROFILE\.harrier\ca.crt"
```

### Firefox (Windows)

Firefox requires separate certificate installation:

1. Open Firefox: `about:preferences#privacy`
2. Scroll to "Certificates" → "View Certificates"
3. Go to "Authorities" tab
4. Click "Import..."
5. Navigate to `%USERPROFILE%\.harrier\ca.crt`
6. Check "Trust this CA to identify websites"
7. Click "OK"

---

## Browser Proxy Configuration

After installing the certificate, configure your browser to use the proxy:

### Chrome/Chromium

**macOS/Linux:**
```bash
# Launch Chrome with proxy
google-chrome --proxy-server="http://localhost:8080"
```

**Windows:**
```powershell
chrome.exe --proxy-server="http://localhost:8080"
```

**Or use system proxy settings:**
- macOS: System Preferences → Network → Advanced → Proxies
- Linux: Settings → Network → Network Proxy
- Windows: Settings → Network & Internet → Proxy

### Firefox

1. Go to `about:preferences#general`
2. Scroll to "Network Settings"
3. Click "Settings..."
4. Select "Manual proxy configuration"
5. Set HTTP Proxy: `localhost`, Port: `8080`
6. Check "Also use this proxy for HTTPS"
7. Click "OK"

### Safari (macOS)

1. System Preferences → Network
2. Select your active connection
3. Click "Advanced..."
4. Go to "Proxies" tab
5. Check "Web Proxy (HTTP)" and "Secure Web Proxy (HTTPS)"
6. Set Server: `localhost`, Port: `8080`
7. Click "OK" and "Apply"

### Command-Line Tools (curl, wget, etc.)

```bash
# Set environment variables
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Use with curl
curl -x http://localhost:8080 https://example.com

# Use with wget
wget -e use_proxy=yes -e http_proxy=localhost:8080 https://example.com
```

---

## Usage Examples

### Basic Capture

```bash
# Start proxy and capture to default file (captured.har)
harrier proxy

# Configure browser proxy to localhost:8080
# Browse the target application
# Press Ctrl+C to stop and save
```

### Custom Configuration

```bash
# Use different port
harrier proxy --port 3128

# Specify output file
harrier proxy --output my-app-traffic.har

# Both options
harrier proxy --port 3128 --output api-traffic.har
```

### Post-Capture Workflow

```bash
# Capture traffic
harrier proxy -o app-traffic.har

# Analyze statistics
harrier stats app-traffic.har --verbose

# Filter to specific API
harrier filter app-traffic.har --hosts "api.example.com" -o api-only.har

# Check for security issues
harrier security api-only.har

# Discover API types
harrier discover api-only.har
```

---

## Troubleshooting

### Certificate Errors in Browser

**Problem:** Browser shows "Your connection is not private" or similar warnings.

**Solution:**
1. Verify certificate is installed in system trust store
2. Make sure you selected "Trust for websites/SSL"
3. Restart browser completely
4. For Firefox, remember it needs separate installation

### Proxy Connection Refused

**Problem:** Browser can't connect to proxy.

**Solution:**
1. Verify Harrier proxy is running: you should see "Proxy listening on..."
2. Check firewall isn't blocking port 8080
3. Verify proxy settings are exactly `localhost:8080` (or your custom port)
4. Try `127.0.0.1:8080` instead of `localhost:8080`

### No Traffic Captured

**Problem:** HAR file is empty or shows "No traffic captured".

**Solution:**
1. Verify browser proxy is configured correctly
2. Check you're browsing HTTP/HTTPS sites (not file:// or other protocols)
3. Make sure proxy is still running (didn't crash)
4. Look for error messages in terminal output

### System Proxy Settings Not Working

**Problem:** Setting system-wide proxy doesn't affect Chrome.

**Solution:**
- Chrome may ignore system proxy on some systems
- Use command-line flag: `--proxy-server=http://localhost:8080`
- Or use browser extension for proxy control

### Permission Denied Creating Certificate

**Problem:** Can't create `~/.harrier/` directory.

**Solution:**
```bash
mkdir -p ~/.harrier
chmod 700 ~/.harrier
harrier proxy
```

---

## Security Considerations

### When to Use the Proxy

**Appropriate use cases:**
- Testing your own applications
- Analyzing API traffic for security testing (with authorization)
- Debugging web applications during development
- Creating HAR files for bug reports
- Security research on applications you own or are authorized to test

### When NOT to Use the Proxy

**Do not use for:**
- Intercepting traffic you're not authorized to capture
- Sharing your CA certificate with others
- Leaving the CA certificate permanently installed on production systems
- Capturing credentials or sensitive data without proper security controls

### Best Practices

1. **Protect the private key**: Never share `~/.harrier/ca.key`
2. **Remove when done**: Uninstall the CA certificate when not actively using the proxy
3. **Use dedicated test browsers**: Set up separate browser profiles for proxy testing
4. **Be aware of captured data**: HAR files may contain sensitive information (tokens, credentials, PII)
5. **Secure your HAR files**: Treat captured HAR files as confidential

### Removing the Certificate

**macOS:**
```bash
# Open Keychain Access
# Search for "Harrier MITM Proxy CA"
# Right-click → Delete "Harrier MITM Proxy CA"
# Or command line:
security delete-certificate -c "Harrier MITM Proxy CA"
```

**Linux (Ubuntu/Debian):**
```bash
sudo rm /usr/local/share/ca-certificates/harrier-ca.crt
sudo update-ca-certificates --fresh
```

**Windows:**
```powershell
# Open certmgr.msc
# Navigate to Trusted Root Certification Authorities → Certificates
# Find "Harrier MITM Proxy CA"
# Right-click → Delete
# Or command line:
certutil -delstore Root "Harrier MITM Proxy CA"
```

**Firefox:**
- Go to `about:preferences#privacy`
- Certificates → View Certificates → Authorities
- Find "Harrier" and delete

---

## Advanced Usage

### Using Custom CA Certificate

If you need to use a specific CA certificate:

```bash
harrier proxy --cert /path/to/custom-ca.crt --key /path/to/custom-ca.key
```

This is useful for:
- Using a company CA certificate
- Maintaining consistent certificates across a team
- Using certificates from existing PKI infrastructure

### Capturing Specific Application Traffic

```bash
# Start proxy
harrier proxy -o app-traffic.har

# Run your application with proxy environment variables
HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8080 ./my-app

# Or for Docker containers
docker run -e HTTP_PROXY=http://host.docker.internal:8080 \
           -e HTTPS_PROXY=http://host.docker.internal:8080 \
           my-image
```

### Chaining with Other Tools

```bash
# Capture traffic, then analyze with jq
harrier proxy -o traffic.har
jq '.log.entries[].request.url' traffic.har

# Filter and pipe to other HAR tools
harrier filter traffic.har --hosts "*.api.com" | other-har-tool

# Combine with watch for live analysis
harrier proxy -o traffic.har &
watch -n 5 'harrier stats traffic.har'
```

---

## Integration with StackHawk

Harrier proxy is designed to work seamlessly with StackHawk's HawkScan:

```bash
# 1. Capture application traffic
harrier proxy -o app-traffic.har

# 2. Filter to your application's API
harrier filter app-traffic.har --hosts "api.example.com" -o api.har

# 3. Use with HawkScan (assuming you have stackhawk.yml configured)
hawk scan app-traffic.har
```

This workflow allows you to:
- Capture real user interactions
- Generate authenticated API traffic
- Discover API endpoints automatically
- Feed realistic traffic patterns to security testing

---

## Additional Resources

- [HAR Specification](https://w3c.github.io/web-performance/specs/HAR/Overview.html)
- [StackHawk Documentation](https://docs.stackhawk.com/)
- [Harrier GitHub Repository](https://github.com/yourusername/harrier)

## Support

If you encounter issues:
1. Check this troubleshooting guide
2. Run with verbose logging: `harrier proxy --verbose`
3. Check the output in your terminal for error messages
4. Review HAR file with: `harrier stats captured.har`
