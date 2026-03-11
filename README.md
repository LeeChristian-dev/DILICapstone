# DILI Capstone

A Chrome extension for detecting and labeling DILI (Drug-Induced Liver Injury) risk factors.

## Project Structure

- **manifest.json** - Extension configuration file
- **content.js** - Content script that runs in webpage context
- **background.js** - Background service worker
- **styles/** - CSS stylesheets
  - post-risk-label.css - Styles for risk labels
- **popup/** - Extension popup interface
  - popup.html - Popup markup
  - popup.css - Popup styles
  - popup.js - Popup functionality
- **warning/** - Warning page components
  - warning.html - Warning page markup
  - warning.css - Warning page styles
  - warning.js - Warning page functionality
- **assets/icons/** - Icon assets for the extension

## Getting Started

1. Clone this repository
2. Load the extension in Chrome: chrome://extensions/ → Load unpacked
3. Select the DILICAPSTONE directory

## Development

Add your extension logic to the respective files based on their purpose.
