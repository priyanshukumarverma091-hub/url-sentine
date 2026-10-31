# URL Sentinel

### A Rule-Based URL Security Analyzer

URL Sentinel is a Python-based security tool designed to analyze URLs and identify potentially suspicious characteristics using predefined security rules.

The application evaluates multiple URL parameters, calculates a risk score, and generates a security analysis report through a simple web interface.

## Features

- HTTPS Detection
- IP Address Detection
- Suspicious Keyword Detection
- URL Length Analysis
- Special Character Detection
- URL Shortener Detection
- DNS Resolution Check
- Risk Score Calculation
- Security Analysis Report
- Responsive Web Interface

## Technologies Used

- Python
- Regular Expressions
- Socket Programming
- IP Address Validation

## Project Structure

    URL-Sentinel/
    |
    |-- new.py
    |-- README.md

## Installation and Setup

### 1. Clone the Repository

    git clone https://github.com/priyanshukumarverma091-hub/url-sentine.git

### 2. Navigate to the Project Directory

    cd url-sentine

### 4. Run the Application

    python new.py

### 5. Open in Browser

    http://127.0.0.1:5000

## Risk Classification

| Risk Score | Classification |
|------------|----------------|
| 0–29       | Low Risk       |
| 30–59      | Medium Risk    |
| 60–100     | High Risk      |

## How It Works

1. The user enters a website URL.
2. The application passes the URL to the Python analyzer.
3. The analyzer evaluates the URL using predefined security rules.
4. Suspicious indicators contribute to the overall risk score.
5. The application generates a security report displaying the score, classification, and detected indicators.

## Project Objective

The objective of URL Sentinel is to explore fundamental cybersecurity concepts through practical implementation.

The project demonstrates how Python programming, URL parsing, network operations, and rule-based analysis can be combined to build a basic URL security analysis tool.

## Limitations

- Uses predefined detection rules.
- Does not use AI or machine learning.
- Does not connect to external threat intelligence databases.
- May produce false positives and false negatives.
- A low-risk classification does not guarantee website safety.

## Future Improvements

- Advanced URL validation
- Improved phishing detection rules
- Detailed domain analysis
- Security report enhancements

## Author

**Priyanshu Kumar Verma**

GitHub: priyanshukumarverma091-hub

## License

This project is intended for educational and research purposes.
