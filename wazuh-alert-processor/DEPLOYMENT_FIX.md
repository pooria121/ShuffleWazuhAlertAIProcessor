# Deployment Fix for Shuffle Connection Error

## Problem
```
{"success":false,"reason":"Failed to connect to app http://wazuh-alert-processor_1-0-0:33337/api/v1/run in swarm. Try the action again, restart Orborus if this is recurring, or contact support@shuffler.io.","details":"Failed connecting to app wazuh-alert-processor_1-0-0. Is the Docker image available?"}
```

## Root Cause
The app wasn't running as a proper web server on the expected port (33337) that Shuffle uses for communication.

## Fixes Applied

### 1. Updated app.py
```python
if __name__ == "__main__":
    WazuhAlertProcessor.run(host="0.0.0.0", port=33337)
```
- Now binds to all interfaces (0.0.0.0) on port 33337
- Allows Shuffle to connect from external containers

### 2. Updated Dockerfile
```dockerfile
EXPOSE 33337
```
- Explicitly exposes port 33337 for container networking
- Ensures port is available for Shuffle communication

### 3. Updated requirements.txt
```
requests==2.31.0
flask==2.3.3
walkoff_app_sdk
```
- Added Flask dependency to ensure web server functionality

## Deployment Steps

1. **Commit Changes**:
   ```bash
   git add .
   git commit -m "Fix: Add proper Flask server configuration for Shuffle deployment"
   git push origin main
   ```

2. **Redeploy in Shuffle**:
   - Go to Apps → Find your app → Update/Redeploy
   - Or remove and re-add from GitHub

3. **Test Connection**:
   - Try running the workflow again
   - The app should now be accessible on port 33337

## Expected Result
- ✅ App container starts successfully
- ✅ Flask server runs on 0.0.0.0:33337
- ✅ Shuffle can connect to the app
- ✅ Workflow executes without connection errors

## Troubleshooting

If still getting connection errors:
1. Check Shuffle logs for more details
2. Verify the app deployed successfully in Shuffle Apps section
3. Restart Orborus if the issue persists
4. Check that the Docker image built correctly

The app now follows proper Shuffle deployment practices with correct networking configuration.