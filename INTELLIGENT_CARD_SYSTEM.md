# Intelligent Card System

**AI-Powered Card Testing with EMVCo Compliance and Reverse Merchant Testing**

The Intelligent Card System transforms traditional smartcards into intelligent, self-learning entities that:

- **Learn** from every interaction and vulnerability scan
- **Comply** with EMVCo and EMV RFID specifications
- **Test merchants** instead of being tested by them
- **Log everything** on-card for post-analysis

---

## 🎯 Overview

Traditional EMV testing: **Merchant tests card** → Card responds  
Intelligent Card System: **Card tests merchant** → Learns and adapts

### Core Components

1. **AI Learning System** (`ai_learning_system.py`)
   - Continuous learning from vulnerability scans
   - Pattern recognition in successful attacks
   - Attack success prediction using ML
   - Session-based learning with before/after analysis

2. **EMVCo Card Personalizer** (`emvco_card_personalizer.py`)
   - EMVCo v2.10 compliant personalization
   - EMV RFID specifications support
   - TLV encoding for all card data
   - Luhn validation and data integrity

3. **Merchant Tester Applet** (`MerchantTesterApplet.java`)
   - JavaCard applet with 10 merchant tests
   - On-card logging of test results
   - Real-time vulnerability detection
   - EMV transaction flow analysis

4. **Integration Module** (`intelligent_card_system.py`)
   - Orchestrates complete workflow
   - Unified API for all operations
   - Session management and reporting

---

## 🚀 Quick Start

### Installation

```bash
# Install Python dependencies
pip install -r requirements.txt

# Optional: Install scikit-learn for ML features
pip install scikit-learn numpy

# Build JavaCard applet (optional)
cd javacard/applet
./gradlew convertCap
```

### Basic Usage

#### 1. Personalize an Intelligent Card

```python
from modules.intelligent_card_system import IntelligentCardSystem

# Initialize system
ics = IntelligentCardSystem()

# Generate test card data
card_data = ics.personalizer.generate_test_card("VISA")

# Personalize card
ics.personalize_intelligent_card(card_data)
```

#### 2. Run AI Learning Session

```python
# Run vulnerability scan with AI learning
session_summary = ics.run_learning_session(
    card_atr="3B6F00FF000000000000000000000000",
    techniques=["timing", "dpa", "fault_injection", "protocol_exploitation"]
)

print(f"Success rate: {session_summary['success_rate']}")
print(f"Patterns learned: {session_summary['patterns_learned']}")
```

#### 3. Test a Merchant

```python
# Run 10 merchant tests
results = ics.run_merchant_tests(
    card_interface=card,
    merchant_id="MERCHANT_001"
)

print(f"Tests passed: {results['summary']['passed']}/10")
print(f"Vulnerabilities: {results['summary']['vulnerabilities_found']}")
```

#### 4. Generate Intelligence Report

```python
# Generate comprehensive report
report = ics.generate_intelligence_report()
print(report)
```

---

## 📚 Detailed Documentation

### AI Learning System

The AI Learning System continuously learns from interactions:

**Features:**

- SQLite database for structured learning data
- Machine learning models (Random Forest, DBSCAN)
- Pattern recognition in attack sequences
- Timing-based vulnerability detection
- Attack success prediction

**Usage:**

```python
from modules.ai_learning_system import AILearningSystem

ai = AILearningSystem()

# Start a learning session
session_id = ai.start_session("vulnerability_scan", {"ATR": "..."})

# Log attack attempts
ai.log_attempt(
    attack_type="timing",
    target="pin_verification",
    parameters={"iterations": 1000},
    response_sw=(0x90, 0x00),
    response_data=b'\x12\x34',
    timing_ns=1500000,
    success=True
)

# End session and learn
summary = ai.end_session(secrets_extracted=5)

# Get recommendations for future attacks
recommendations = ai.get_recommended_attacks(card_atr)
```

**Learning Process:**

1. **Pre-scan state capture** - Card state before attack
2. **Attack execution** - Run vulnerability techniques
3. **Post-scan state capture** - Card state after attack
4. **Pattern analysis** - Identify what worked
5. **Knowledge update** - Store patterns in database
6. **Model training** - Improve ML predictions

**Database Schema:**

- `scan_sessions` - Vulnerability scan metadata
- `attack_attempts` - Individual attack records
- `merchant_profiles` - Merchant behavior data
- `card_signatures` - Card behavioral fingerprints
- `knowledge_patterns` - Learned attack patterns

### EMVCo Card Personalizer

Personalizes cards according to EMVCo specifications:

**Features:**

- EMVCo v2.10 specification compliance
- EMV RFID (ISO/IEC 14443 Type A/B) support
- NFC Forum Type 4 Tag compatibility
- TLV encoding for all data objects
- Luhn algorithm validation

**Usage:**

```python
from modules.emvco_card_personalizer import EMVCoCardPersonalizer

personalizer = EMVCoCardPersonalizer(compliance_mode="strict")

# Define card data
card_data = {
    "PAN": "4761120010000492",
    "expiry_date": "12/25",
    "cardholder_name": "JOHN DOE",
    "CVV": "123",
    "card_type": "VISA",
    "service_code": "201",
    "country_code": "840",
    "currency_code": "840"
}

# Personalize card
success = personalizer.personalize_card(card_data, card_interface)

# Verify EMVCo compliance
compliance = personalizer.verify_emvco_compliance(card_interface)
print(f"Compliant: {compliance['compliant']}")
```

**EMV Tags Supported:**

| Tag   | Description                    |
|-------|--------------------------------|
| `5A`  | PAN (Primary Account Number)   |
| `5F24`| Expiry Date                    |
| `5F20`| Cardholder Name                |
| `57`  | Track 2 Equivalent Data        |
| `82`  | Application Interchange Profile|
| `94`  | Application File Locator       |
| `8E`  | Cardholder Verification Method |
| `9F09`| Application Version            |
| `9F36`| Application Transaction Counter|

**Validation Rules:**

- PAN: 13-19 digits, Luhn check
- Expiry: MM/YY format, not expired
- CVV: 3-4 digits
- Cardholder name: 2-26 characters

### Merchant Tester Applet

JavaCard applet that performs 10 tests on merchants:

**Tests Performed:**

1. **Application Selection** - Validates proper SELECT command
2. **GPO Compliance** - Checks PDOL data format
3. **READ RECORD Handling** - Validates record reading
4. **PIN Verification Flow** - Tests PIN processing
5. **GENERATE AC Request** - Validates cryptogram request
6. **Cryptogram Processing** - Tests cryptogram validation
7. **Authorization Logic** - Checks online/offline logic
8. **Terminal Capabilities** - Verifies terminal features
9. **Transaction Limits** - Tests amount limits
10. **Error Handling** - Validates error responses

**Custom Commands:**

| CLA  | INS  | Command          | Description                |
|------|------|------------------|----------------------------|
| `80` | `10` | RUN_TESTS        | Start merchant tests       |
| `80` | `20` | GET_TEST_RESULTS | Retrieve test results      |
| `80` | `30` | CLEAR_LOG        | Clear on-card log          |
| `80` | `40` | GET_TEST_COUNT   | Get completed test count   |

**Building the Applet:**

```bash
cd javacard/applet
./gradlew convertCap

# Deploy to card
./gradlew deployCap
```

**Reading Test Results:**

```python
# Send GET_TEST_RESULTS command
apdu = [0x80, 0x20, 0x00, 0x00, 0x00]
response, sw1, sw2 = card.transmit(apdu)

# Parse results (1 byte per test)
for i, result in enumerate(response[:10]):
    status = {0x00: "NOT_RUN", 0x01: "PASSED", 
              0x02: "FAILED", 0x03: "WARNING"}[result]
    print(f"Test {i+1}: {status}")
```

---

## 🔬 Advanced Features

### Attack Success Prediction

The AI can predict attack success before execution:

```python
prediction, confidence = ai.predict_attack_success(
    attack_type="timing",
    target="pin_verification",
    timing_estimate=1500000  # nanoseconds
)

print(f"Predicted success: {prediction} ({confidence:.0%} confidence)")
```

### Merchant Profiling

Build profiles of merchant behaviors:

```python
# Profile merchant based on test results
ai.profile_merchant("MERCHANT_001", test_results)

# Query merchant profile
cursor = ai.conn.cursor()
cursor.execute('''
    SELECT vulnerability_score, observed_behaviors
    FROM merchant_profiles
    WHERE merchant_id = ?
''', ("MERCHANT_001",))

profile = cursor.fetchone()
print(f"Vulnerability score: {profile[0]:.2f}")
```

### Pattern-Based Learning

The system learns attack patterns automatically:

```python
# Query learned patterns
cursor = ai.conn.cursor()
cursor.execute('''
    SELECT pattern_type, confidence, description
    FROM knowledge_patterns
    WHERE success_count > 0
    ORDER BY confidence DESC
''')

for pattern_type, confidence, description in cursor.fetchall():
    print(f"{pattern_type}: {description} ({confidence:.0%})")
```

---

## 📊 Example Workflow

Complete workflow demonstrating all features:

```python
from modules.intelligent_card_system import IntelligentCardSystem

# 1. Initialize system
ics = IntelligentCardSystem()

# 2. Create and personalize test card
print("Step 1: Personalizing card...")
card_data = ics.personalizer.generate_test_card("MASTERCARD")
ics.personalize_intelligent_card(card_data)

# 3. Run AI learning session
print("\nStep 2: Running AI learning session...")
session = ics.run_learning_session(
    card_atr="3B6F00FF000000000000000000000000",
    techniques=["timing", "protocol_exploitation"]
)

print(f"  Success rate: {session['success_rate']}")
print(f"  New patterns: {session['patterns_learned']}")

# 4. Test merchant
print("\nStep 3: Testing merchant...")
merchant_results = ics.run_merchant_tests(
    card_interface=card,
    merchant_id="BLANDY_FLOWERS"
)

print(f"  Tests passed: {merchant_results['summary']['passed']}/10")
print(f"  Vulnerabilities: {merchant_results['summary']['vulnerabilities_found']}")

# 5. Extract on-card data
print("\nStep 4: Extracting on-card logs...")
card_data = ics.extract_on_card_data(card)
print(f"  Tests logged: {len(card_data['test_results'])}")

# 6. Generate intelligence report
print("\nStep 5: Generating intelligence report...")
report = ics.generate_intelligence_report()

# 7. Get AI statistics
print("\nFinal Statistics:")
ics.ai.print_summary()

# 8. Close system
ics.close()
```

---

## 🛠️ CLI Tools

### AI Learning System CLI

```bash
# View statistics
python modules/ai_learning_system.py --stats

# Get attack recommendations
python modules/ai_learning_system.py --recommend "3B6F00FF000000000000000000000000"
```

### EMVCo Personalizer CLI

```bash
# Generate test card
python modules/emvco_card_personalizer.py --generate-test VISA

# Validate card data
python modules/emvco_card_personalizer.py --validate card_data.json

# Personalize card
python modules/emvco_card_personalizer.py --personalize card_data.json --mode strict
```

### Intelligent Card System CLI

```bash
# Personalize test card
python modules/intelligent_card_system.py personalize --card-type VISA --test-card

# Run learning session
python modules/intelligent_card_system.py learn --atr 3B6F00... --techniques timing dpa

# Generate report
python modules/intelligent_card_system.py report

# Show statistics
python modules/intelligent_card_system.py stats
```

---

## 📁 File Structure

```
GREENWIRE/
├── modules/
│   ├── ai_learning_system.py           # AI learning engine
│   ├── emvco_card_personalizer.py      # EMVCo personalization
│   ├── intelligent_card_system.py      # Integration module
│   └── advanced_vulnerability_fuzzer.py # Vulnerability testing
│
├── javacard/applet/src/main/java/com/greenwire/merchanttest/
│   └── MerchantTesterApplet.java       # On-card merchant tester
│
├── ai_knowledge_base/
│   ├── learning.db                     # SQLite knowledge base
│   ├── knowledge_cache.pkl             # Cached patterns
│   └── attack_predictor.pkl            # ML models
│
├── personalization_records/
│   └── personalization_*.json          # Personalization audit trail
│
├── intelligent_card_sessions/
│   ├── merchant_tests_*.json           # Merchant test results
│   └── intelligence_report_*.md        # Intelligence reports
│
└── INTELLIGENT_CARD_SYSTEM.md          # This file
```

---

## 🔍 Technical Details

### AI Learning Algorithm

1. **Session Management**
   - Start session → Capture pre-state
   - Execute attacks → Log all attempts
   - End session → Analyze and learn

2. **Pattern Recognition**
   - Attack sequence patterns
   - Timing differentials
   - Parameter combinations
   - Response patterns

3. **Machine Learning**
   - Random Forest for attack classification
   - DBSCAN for behavior clustering
   - StandardScaler for feature normalization

4. **Knowledge Storage**
   - SQLite for structured data
   - Pickle for ML models
   - JSON for session logs

### EMVCo Compliance

**Standards Implemented:**

- EMVCo Contactless Specifications v2.10
- ISO/IEC 7816-4 (APDU)
- ISO/IEC 14443 Type A/B (RFID)
- NFC Forum Type 4 Tag
- GlobalPlatform 2.3.1

**Data Encoding:**

- BER-TLV encoding for all objects
- BCD encoding for numeric data
- ASCII encoding for text data
- Proper padding and alignment

### JavaCard Applet Architecture

**Memory Allocation:**

- Test results: 10 bytes (1 per test)
- Test log: 512 bytes (detailed logs)
- Terminal capabilities: 3 bytes
- Transaction amount: 6 bytes
- Temp buffer: 256 bytes

**Execution Flow:**

```
SELECT → Test 1 (Application Selection)
  ↓
GPO → Test 2 (GPO Compliance)
    → Test 8 (Terminal Capabilities)
    → Test 9 (Transaction Limits)
  ↓
READ RECORD → Test 3 (Read Handling)
  ↓
VERIFY → Test 4 (PIN Flow)
  ↓
GENERATE AC → Test 5 (AC Request)
            → Test 6 (Cryptogram)
            → Test 7 (Authorization)
  ↓
Error handling → Test 10 (Error Handling)
```

---

## 🎓 Examples

### Example 1: Simple Learning Session

```python
from modules.intelligent_card_system import IntelligentCardSystem

ics = IntelligentCardSystem()

# Run quick learning session
summary = ics.run_learning_session(
    card_atr="3B6F00FF000000000000000000000000"
)

print(f"Learned {summary['patterns_learned']} new patterns")
ics.close()
```

### Example 2: EMVCo Test Card

```python
from modules.emvco_card_personalizer import EMVCoCardPersonalizer

personalizer = EMVCoCardPersonalizer()

# Generate all card types
for card_type in ["VISA", "MASTERCARD", "AMEX", "DISCOVER", "JCB"]:
    card_data = personalizer.generate_test_card(card_type)
    print(f"{card_type}: {card_data['PAN']}")
```

### Example 3: Merchant Vulnerability Scan

```python
from modules.intelligent_card_system import IntelligentCardSystem

ics = IntelligentCardSystem()

# Test multiple merchants
merchants = ["MERCHANT_A", "MERCHANT_B", "MERCHANT_C"]

for merchant_id in merchants:
    results = ics.run_merchant_tests(card, merchant_id)
    vuln_count = results['summary']['vulnerabilities_found']
    print(f"{merchant_id}: {vuln_count} vulnerabilities")

ics.close()
```

---

## 🐛 Troubleshooting

### Issue: ML models not training

**Solution:** Install scikit-learn:

```bash
pip install scikit-learn numpy
```

### Issue: JavaCard applet build fails

**Solution:** Check JavaCard SDK installation:

```bash
cd javacard/applet
./gradlew --info convertCap
```

### Issue: Card communication errors

**Solution:** Verify card reader connection:

```python
from smartcard.System import readers

r = readers()
print(f"Available readers: {r}")
```

---

## 📖 References

- **EMVCo Specifications**: <https://www.emvco.com/specifications/>
- **ISO/IEC 7816-4**: Smart card APDU protocol
- **ISO/IEC 14443**: Contactless cards (RFID)
- **GlobalPlatform**: <https://globalplatform.org/>
- **JavaCard**: <https://docs.oracle.com/javacard/>

---

## 🤝 Contributing

Contributions welcome! Areas of interest:

- Additional merchant tests
- New AI learning algorithms
- EMVCo 3.0 support
- Real-world card interface integration

---

## 📜 License

See main GREENWIRE license.

---

## 🎯 Summary

The Intelligent Card System provides:

✅ **AI Learning** - Continuous improvement from interactions  
✅ **EMVCo Compliance** - Standards-compliant personalization  
✅ **Reverse Testing** - Cards test merchants, not vice versa  
✅ **On-Card Logging** - All data logged on the card itself  
✅ **Pattern Recognition** - Learn what works, predict success  
✅ **Merchant Profiling** - Build vulnerability profiles  

**Result:** Intelligent cards that learn, adapt, and test merchants while remaining EMVCo compliant.

---

*For more information, see GREENWIRE main documentation.*
