$env:SECRET_KEY="demo-secret-123"
$env:DASH_USER="admin"
$env:DASH_PASS="12345678"
$env:DASHBOARD_SECRET="supersecret"

Write-Host "Installing requirements..."
pip install -r requirements.txt

Write-Host "Starting Mock SDN Controller..."
Start-Process python -ArgumentList "controller.py" -WindowStyle Normal

Write-Host "Starting Mock Topology..."
Start-Process python -ArgumentList "topology.py" -WindowStyle Normal

Write-Host "Starting Dashboard..."
Start-Process python -ArgumentList "dashboard.py" -WindowStyle Normal

Write-Host "All services started! The dashboard is running at http://localhost:5000"
Write-Host "You can close this window now."
Start-Sleep -Seconds 5
