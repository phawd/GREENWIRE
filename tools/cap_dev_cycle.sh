#!/bin/bash
# GREENWIRE .cap Development & Testing Workflow
# Usage: ./tools/cap_dev_cycle.sh [applet_name]

set -e

APPLET_NAME=${1:-"FuzzingApplet"}
JAVACARD_DIR="javacard/applet"
BASE_DIR=$(pwd)

echo "🔄 Starting .cap development cycle for ${APPLET_NAME}..."

# Check if we're in the right directory
if [ ! -d "$JAVACARD_DIR" ]; then
    echo "❌ JavaCard directory not found. Run from GREENWIRE root."
    exit 1
fi

# Build phase
echo "🔨 Building applet..."
cd "$JAVACARD_DIR"

# Clean previous builds
if [ -d "build" ]; then
    rm -rf build
fi

# Build with specific applet
./gradlew convertCap -PappletClass="com.greenwire.fuzz.${APPLET_NAME}" -q

if [ $? -eq 0 ]; then
    echo "✅ Build successful"
    
    # Find the generated .cap file
    CAP_FILE=$(find build -name "*.cap" -type f | head -1)
    if [ -n "$CAP_FILE" ]; then
        echo "📦 Generated: $CAP_FILE"
        
        # Deploy phase (if card available)
        echo "🚀 Attempting deployment..."
        ./gradlew deployCap -q
        
        if [ $? -eq 0 ]; then
            echo "✅ Deployment successful"
            
            # Test phase
            cd "$BASE_DIR"
            echo "🧪 Running GREENWIRE tests..."
            
            # Test with specific AID (adjust as needed)
            TEST_AID="A0000006230146555A5A"
            
            # Basic APDU test
            echo "  Testing SELECT command..."
            python greenwire.py apdu --command "00A4040007${TEST_AID}" --verbose || true
            
            # Fuzzing test
            echo "  Running targeted fuzzing (50 iterations)..."
            python greenwire.py testing ai-vuln \
                --iterations 50 \
                --strategy mixed \
                --summary \
                --seed 42 || true
            
            echo "🎯 Testing complete - check artifacts/ for detailed results"
        else
            echo "⚠️  Deployment failed (no card detected?)"
            echo "   You can still test the .cap file manually:"
            echo "   java -jar ../../lib/GlobalPlatformPro.jar --install $CAP_FILE"
        fi
    else
        echo "❌ No .cap file generated"
        exit 1
    fi
else
    echo "❌ Build failed"
    exit 1
fi

cd "$BASE_DIR"
echo "✨ Development cycle complete!"