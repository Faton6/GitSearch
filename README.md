# GitSearch

![logo_gitsearch](https://github.com/Faton6/GitSearch/assets/76423174/d5f4b8ff-9e15-435c-a0ff-761e055be98e)

## ⚪️ What is this?
GitSearch is a universal corporate information and credentials leak scanner designed to monitor open-source code platforms. It helps prevent potential losses by detecting data breaches in a timely manner.

## 🗜️ How does it work?
Our project integrates open-source scanning tools, including TruffleHog, Gitleaks, and Git-Secrets, to perform leak detection in the most effective way possible.

## 🔧 How to use it?
GitSearch utilizes Docker Compose to compile and launch all necessary Docker containers. Simply clone this project and run the following commands:
```
docker-compose-up
```
Don't forget to configure dorks, which are keywords that could be associated with your sensitive data.

## ✅ Running tests
To execute the unit test suite set ``RUN_TESTS = True`` in ``src/constants.py`` and
run ``python gitsearch.py``.  The script will invoke ``pytest`` and exit without
performing any scans.

## 📊 Generating reports
Two HTML report formats can be produced from previously stored scan results.
Open ``config.json`` and set create_report to "yes", start-date, end-date and type of report - technical or business.

After this run gitsearch container and you will get report at the  ``src.reports`` folder.
