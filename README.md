# GitSearch

![logo_gitsearch](https://github.com/Faton6/GitSearch/assets/76423174/a0e55c39-879c-4011-b67e-47e26d83a1d3)

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
