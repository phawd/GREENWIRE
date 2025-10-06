# GREENWIRE Project Overview

## 1. High-Level Summary

GREENWIRE is a comprehensive, modular security testing framework for EMV, smartcard, NFC, and JavaCard research. It provides a unified Python CLI for a wide range of security testing activities, from low-level APDU communication to high-level cryptographic attacks.

The framework is designed for both interactive use through a menu-driven interface and for automated scripting and programmatic use. A key feature of GREENWIRE is its self-contained, offline-first design, particularly for its JavaCard toolchain, allowing for development and deployment in environments without internet access.

## 2. Architecture

The GREENWIRE framework is built on a modular architecture that separates core system functionality from specialized security modules.

### 2.1. Core System (`core/`)

The `core/` directory contains the foundational components of the framework, including:

*   **Configuration Management (`core/config.py`):** Manages environment-based configuration, hardware settings, and attack parameters.
*   **Logging System (`core/logging_system.py`):** Provides a unified logging infrastructure.
*   **NFC Manager (`core/nfc_manager.py`):** A unified interface for interacting with various NFC readers.
*   **Module Manager (`core/module_manager.py`):** Handles dynamic loading and lifecycle management of specialized modules.
*   **Fuzzing Engine (`core/fuzzing_engine.py`):** A generic framework for fuzzing smartcard protocols.

### 2.2. Specialized Modules (`modules/`)

The `modules/` directory contains domain-specific functionality, organized by security research area:

*   **Emulation (`modules/emulation.py`):** Provides card emulation and simulation capabilities for EMV, MIFARE, and NTAG.
*   **Cryptography (`modules/crypto/`):** Implements a wide range of cryptographic attacks, including those targeting EMV, MIFARE, and NTAG.
*   **NFC Communication (`modules/nfc/`):** Contains protocol-specific handlers for NFC communication.
*   **Testing (`modules/testing/`):** Includes modules for fuzzing and running test vectors.
*   **Tools (`modules/tools/`):** Contains specialized tools such as a card cloner and a vulnerability scanner.

## 3. Offline JavaCard Toolchain

A key feature of GREENWIRE is its fully offline JavaCard development and deployment toolchain. This allows researchers and developers to build, test, and deploy JavaCard applets without requiring an internet connection.

### 3.1. Components

*   **Gradle:** The framework uses Gradle for building and deploying JavaCard applets (`.cap` files).
*   **Local Dependencies:** All necessary JavaCard SDKs, tools, and libraries are included in the repository.
*   **Build Tasks:** The `javacard/applet/build.gradle` file defines two main tasks:
    *   `convertCap`: Compiles Java source code and converts it into a `.cap` file.
    *   `deployCap`: Deploys a `.cap` file to a connected smartcard using GlobalPlatformPro.

### 3.2. Workflow

The typical workflow for building and deploying a JavaCard applet is as follows:

1.  **Verify Environment:** Run `python tools/verify_java_static_setup.py` to ensure the environment is correctly configured.
2.  **Build Applet:** Use the `gradlew -p javacard/applet convertCap` command to build the `.cap` file.
3.  **Deploy Applet:** Use the `gradlew -p javacard/applet deployCap` command to deploy the `.cap` file to a smartcard.

## 4. Usage

GREENWIRE can be used in several ways:

*   **Interactive Menu:** Run `python greenwire.py --menu` to launch an interactive, menu-driven interface that guides the user through various tasks.
*   **Command-Line Interface (CLI):** Execute specific commands directly from the command line (e.g., `python greenwire.py apdu --list-readers`).
*   **Programmatic Usage:** Import and use GREENWIRE's modules and functions in your own Python scripts.

## 5. Key Files and Directories

*   `greenwire.py`: The main entry point for the CLI and interactive menu.
*   `GREENWIRE/`: The main project directory.
*   `GREENWIRE/core/`: Core system functionality.
*   `GREENWIRE/modules/`: Specialized security modules.
*   `GREENWIRE/javacard/`: JavaCard-related files, including the Gradle build script.
*   `GREENWIRE/docs/`: Project documentation.
*   `global_defaults.json`: The main configuration file.
*   `requirements.txt`: A list of Python dependencies.
