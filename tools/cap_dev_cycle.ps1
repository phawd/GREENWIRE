# GREENWIRE .cap Development & Testing Workflow (PowerShell)
# Usage: .\tools\cap_dev_cycle.ps1 [-AppletName "FuzzingApplet"]

param(
    [string]$AppletName = "FuzzingApplet"
)

$JavaCardDir = "javacard\applet"
$BaseDir = Get-Location

Write-Host "🔄 Starting .cap development cycle for $AppletName..." -ForegroundColor Green

# Check if we're in the right directory
if (-not (Test-Path $JavaCardDir)) {
    Write-Host "❌ JavaCard directory not found. Run from GREENWIRE root." -ForegroundColor Red
    exit 1
}

try {
    # Build phase
    Write-Host "🔨 Building applet..." -ForegroundColor Yellow
    Set-Location $JavaCardDir
    
    # Clean previous builds
    if (Test-Path "build") {
        Remove-Item -Recurse -Force "build"
    }
    
    # Build with specific applet
    $buildCmd = ".\gradlew.bat convertCap -PappletClass=com.greenwire.fuzz.$AppletName -q"
    Write-Host "Running: $buildCmd" -ForegroundColor Cyan
    
    Invoke-Expression $buildCmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Build successful" -ForegroundColor Green
        
        # Find the generated .cap file
        $capFile = Get-ChildItem -Path "build" -Filter "*.cap" -Recurse | Select-Object -First 1
        
        if ($capFile) {
            Write-Host "📦 Generated: $($capFile.FullName)" -ForegroundColor Cyan
            
            # Deploy phase (if card available)
            Write-Host "🚀 Attempting deployment..." -ForegroundColor Yellow
            
            $deployCmd = ".\gradlew.bat deployCap -q"
            Invoke-Expression $deployCmd
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "✅ Deployment successful" -ForegroundColor Green
                
                # Test phase
                Set-Location $BaseDir
                Write-Host "🧪 Running GREENWIRE tests..." -ForegroundColor Yellow
                
                # Test with specific AID (adjust as needed)
                $testAID = "A0000006230146555A5A"
                
                # Basic APDU test
                Write-Host "  Testing SELECT command..." -ForegroundColor Gray
                python greenwire.py apdu --command "00A4040007$testAID" --verbose
                
                # Fuzzing test
                Write-Host "  Running targeted fuzzing (50 iterations)..." -ForegroundColor Gray
                python greenwire.py testing ai-vuln `
                    --iterations 50 `
                    --strategy mixed `
                    --summary `
                    --seed 42
                
                Write-Host "🎯 Testing complete - check artifacts/ for detailed results" -ForegroundColor Green
            } else {
                Write-Host "⚠️  Deployment failed (no card detected?)" -ForegroundColor Yellow
                Write-Host "   You can still test the .cap file manually:" -ForegroundColor Gray
                Write-Host "   java -jar ..\..\lib\GlobalPlatformPro.jar --install $($capFile.FullName)" -ForegroundColor Gray
            }
        } else {
            Write-Host "❌ No .cap file generated" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "❌ Build failed" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ Error occurred: $_" -ForegroundColor Red
    exit 1
} finally {
    Set-Location $BaseDir
}

Write-Host "✨ Development cycle complete!" -ForegroundColor Magenta