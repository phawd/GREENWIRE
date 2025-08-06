
# GREENWIRE Setup Instructions

1. Clone repository:
	```bash
	git clone https://github.com/phawd/GREENWIRE.git
	```
2. Install dependencies:
	```bash
	pip install -r requirements.txt
	```
3. (Optional, for field/production use) Set up your CA key/certificate:
	- Edit `ca_keys.json` to add your CA key/cert (see README.md for format).
	- Validate your CA key/cert by running:
	  ```bash
	  python greenwire.py issuance --csv-output cards.csv --hardware --profile pcsc --ca-file ca_keys.json
	  ```
	- See README.md and README_DETAILED.md for more details on CA key/cert usage.
4. Run tests:
	```bash
	pytest tests/
	```
