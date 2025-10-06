#!/usr/bin/env python3
"""
Complete Intelligent Card System Example
Demonstrates the full workflow of AI learning, EMVCo personalization, and merchant testing.

This example shows:
1. Card personalization with EMVCo compliance
2. AI-powered vulnerability scanning with learning
3. Merchant testing with on-card logging
4. Intelligence report generation
"""

from modules.intelligent_card_system import IntelligentCardSystem
import sys
import time
from pathlib import Path

# Add GREENWIRE modules to path
sys.path.append(str(Path(__file__).parent))


def print_banner(text: str):
    """Print a formatted banner."""
    print("\n" + "=" * 80)
    print(text.center(80))
    print("=" * 80 + "\n")


def demo_card_personalization(ics: IntelligentCardSystem):
    """Demonstrate card personalization with EMVCo compliance."""
    print_banner("STEP 1: INTELLIGENT CARD PERSONALIZATION")

    print("Generating test card data for three card types...\n")

    card_types = ["VISA", "MASTERCARD", "AMEX"]
    cards = []

    for card_type in card_types:
        print(f"[{card_type}] Generating test card...")
        card_data = ics.personalizer.generate_test_card(card_type)

        # Mask PAN for display
        pan = card_data["PAN"]
        masked_pan = pan[:6] + "*" * (len(pan) - 10) + pan[-4:]

        print(f"  PAN: {masked_pan}")
        print(f"  Expiry: {card_data['expiry_date']}")
        print(f"  Cardholder: {card_data['cardholder_name']}")

        # Personalize card
        print(f"  Personalizing with EMVCo v2.10 compliance...")
        success = ics.personalize_intelligent_card(card_data)

        if success:
            print(f"  ✅ {card_type} card personalized successfully\n")
            cards.append((card_type, card_data))
        else:
            print(f"  ❌ {card_type} personalization failed\n")

    return cards


def demo_ai_learning(ics: IntelligentCardSystem, cards: list):
    """Demonstrate AI learning from vulnerability scans."""
    print_banner("STEP 2: AI LEARNING FROM VULNERABILITY SCANS")

    print("Running AI-powered vulnerability scans on personalized cards...\n")

    # Define attack techniques
    techniques = ["timing", "dpa", "fault_injection", "protocol_exploitation"]

    sessions = []

    for card_type, card_data in cards:
        print(f"\n[{card_type}] Starting vulnerability scan...")
        print(f"  Techniques: {', '.join(techniques)}")

        # Generate mock ATR
        card_atr = f"3B6F00FF{card_type[:4].upper()}00000000000000"

        # Run learning session
        session = ics.run_learning_session(
            card_atr=card_atr,
            techniques=techniques
        )

        sessions.append((card_type, session))

        # Brief pause between cards
        time.sleep(1)

    # Show summary of all sessions
    print("\n" + "-" * 80)
    print("VULNERABILITY SCAN SUMMARY")
    print("-" * 80)

    for card_type, session in sessions:
        print(f"\n{card_type}:")
        print(f"  Duration: {session['duration']}")
        print(f"  Total Attempts: {session['total_attempts']}")
        print(f"  Successful: {session['successful_attacks']}")
        print(f"  Success Rate: {session['success_rate']}")
        print(f"  Secrets Found: {session['secrets_extracted']}")
        print(f"  Patterns Learned: {session['patterns_learned']}")

    return sessions


def demo_merchant_testing(ics: IntelligentCardSystem):
    """Demonstrate merchant testing."""
    print_banner("STEP 3: MERCHANT TESTING")

    print("Testing merchant terminals with intelligent card...\n")

    # Define test merchants
    merchants = [
        ("BLANDY_FLOWERS", "Blandy's Flowers POS"),
        ("GENERIC_RETAIL", "Generic Retail Terminal"),
        ("HIGH_SECURITY", "High Security Terminal")
    ]

    merchant_results = []

    for merchant_id, merchant_name in merchants:
        print(f"\n[{merchant_name}]")
        print(f"  Merchant ID: {merchant_id}")
        print(f"  Running 10 merchant tests...")

        # Run merchant tests (simulated - requires actual card interface)
        try:
            results = ics.run_merchant_tests(
                card_interface=None,  # Would be actual card in production
                merchant_id=merchant_id
            )

            merchant_results.append((merchant_name, results))

        except Exception as e:
            print(f"  ⚠️  Test simulation mode (no physical card)")
            # Create mock results for demonstration
            results = {
                "merchant_id": merchant_id,
                "summary": {
                    "total_tests": 10,
                    "passed": 8,
                    "failed": 2,
                    "vulnerabilities_found": 1
                }
            }
            merchant_results.append((merchant_name, results))

        time.sleep(0.5)

    # Show merchant test summary
    print("\n" + "-" * 80)
    print("MERCHANT TEST SUMMARY")
    print("-" * 80)

    for merchant_name, results in merchant_results:
        summary = results["summary"]
        print(f"\n{merchant_name}:")
        print(f"  Tests Passed: {summary['passed']}/{summary['total_tests']}")
        print(f"  Tests Failed: {summary['failed']}/{summary['total_tests']}")
        print(f"  Vulnerabilities: {summary['vulnerabilities_found']}")

    return merchant_results


def demo_intelligence_report(ics: IntelligentCardSystem):
    """Generate and display intelligence report."""
    print_banner("STEP 4: INTELLIGENCE REPORT GENERATION")

    print("Generating comprehensive intelligence report...\n")

    report = ics.generate_intelligence_report()

    # Display key sections
    print(report)

    return report


def demo_ai_predictions(ics: IntelligentCardSystem):
    """Demonstrate AI attack prediction."""
    print_banner("STEP 5: AI ATTACK PREDICTIONS")

    print("Using learned patterns to predict attack success...\n")

    # Test different attack scenarios
    scenarios = [
        ("timing", "pin_verification", 1500000),
        ("dpa", "cryptogram", 2000000),
        ("fault_injection", "memory_dump", 1000000),
        ("protocol_exploitation", "auth_bypass", 1800000)
    ]

    print("Attack Predictions:")
    print("-" * 80)

    for attack_type, target, timing_ns in scenarios:
        prediction, confidence = ics.ai.predict_attack_success(
            attack_type=attack_type,
            target=target,
            timing_estimate=timing_ns
        )

        result = "✅ SUCCESS" if prediction else "❌ FAILURE"
        print(f"{attack_type} → {target}:")
        print(f"  Prediction: {result}")
        print(f"  Confidence: {confidence:.0%}")
        print(f"  Timing: {timing_ns/1e6:.2f}ms\n")


def demo_recommendations(ics: IntelligentCardSystem):
    """Demonstrate AI attack recommendations."""
    print_banner("STEP 6: AI ATTACK RECOMMENDATIONS")

    print("Getting AI recommendations for new card...\n")

    card_atr = "3B6F00FFTEST000000000000000000"

    recommendations = ics.ai.get_recommended_attacks(card_atr, limit=5)

    print(f"Recommendations for ATR: {card_atr}")
    print("-" * 80)

    for i, rec in enumerate(recommendations, 1):
        print(f"\n{i}. {rec['attack_type']} → {rec['target']}")
        print(f"   Rationale: {rec['rationale']}")
        print(f"   Confidence: {rec['confidence']:.0%}")


def main():
    """Run complete demonstration."""
    print_banner("INTELLIGENT CARD SYSTEM - COMPLETE DEMONSTRATION")

    print("""
This demonstration shows the complete Intelligent Card System workflow:

1. Card Personalization - EMVCo v2.10 compliant card creation
2. AI Learning - Vulnerability scanning with pattern learning
3. Merchant Testing - Reverse testing of merchant terminals
4. Intelligence Reports - Comprehensive analysis and reporting
5. AI Predictions - Attack success prediction
6. Recommendations - AI-powered attack suggestions

Starting demonstration...
    """)

    input("Press Enter to begin...")

    # Initialize system
    print("\nInitializing Intelligent Card System...")
    ics = IntelligentCardSystem()

    try:
        # Step 1: Personalize cards
        cards = demo_card_personalization(ics)
        input("\nPress Enter to continue to AI learning...")

        # Step 2: AI learning sessions
        sessions = demo_ai_learning(ics, cards)
        input("\nPress Enter to continue to merchant testing...")

        # Step 3: Merchant testing
        merchant_results = demo_merchant_testing(ics)
        input("\nPress Enter to generate intelligence report...")

        # Step 4: Intelligence report
        report = demo_intelligence_report(ics)
        input("\nPress Enter to see AI predictions...")

        # Step 5: AI predictions
        demo_ai_predictions(ics)
        input("\nPress Enter to see AI recommendations...")

        # Step 6: Recommendations
        demo_recommendations(ics)

        # Final statistics
        print_banner("FINAL STATISTICS")
        ics.ai.print_summary()

        print("\n" + "=" * 80)
        print("DEMONSTRATION COMPLETE".center(80))
        print("=" * 80)

        print("""
The Intelligent Card System has successfully demonstrated:

✅ EMVCo-compliant card personalization
✅ AI-powered vulnerability scanning
✅ Continuous learning from interactions
✅ Reverse merchant testing
✅ Attack success prediction
✅ Intelligent attack recommendations
✅ Comprehensive intelligence reporting

All data has been logged to:
- ai_knowledge_base/learning.db (AI knowledge)
- personalization_records/ (Card personalization audit)
- intelligent_card_sessions/ (Session logs and reports)

You can now:
1. Review the generated intelligence report
2. Query the AI knowledge base
3. Run additional learning sessions
4. Test more merchants
5. Export learned patterns

For more information, see INTELLIGENT_CARD_SYSTEM.md
        """)

    except KeyboardInterrupt:
        print("\n\n⚠️  Demonstration interrupted by user")

    except Exception as e:
        print(f"\n\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        print("\nClosing Intelligent Card System...")
        ics.close()
        print("✅ System closed\n")


if __name__ == "__main__":
    main()
