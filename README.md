# Intrusion Detection System

## Overview
This project demonstrates the implementation of an Intrusion Detection System (IDS) using automata theory. The system detects malicious patterns in SQL queries and other inputs by converting regular expressions into finite automata (NFA and DFA).

## Features
- **Regex to Automata Conversion**: Converts regular expressions to NFA (with or without epsilon transitions) and then to DFA.
- **Malicious Pattern Detection**: Detects SQL injection, XSS, and command injection patterns.
- **Dataset Support**: Processes a dataset of SQL queries from a CSV file.
- **DFA Visualization**: Displays the states, transitions, and other details of the DFA.

## Files
- `main.py`: The primary script for detecting malicious patterns in SQL queries.
- `regex_to_automata.py`: Demonstrates the conversion of regex to NFA and DFA, and processes the same dataset.
- `sql_queries.csv`: A sample dataset of SQL queries.

## How to Use
1. **Install Dependencies**:
   Ensure you have Python installed along with the required libraries. Install dependencies using:
   ```bash
   pip install automata-lib
   ```

2. **Prepare Dataset**:
   Add your SQL queries to the `sql_queries.csv` file. Ensure the first row is a header (e.g., `query`).

3. **Run the Scripts**:
   - To detect malicious patterns, run:
     ```bash
     python main.py
     ```
   - To view regex to automata conversion, run:
     ```bash
     python regex_to_automata.py
     ```

4. **View Results**:
   - The `main.py` script will display whether each query is safe or malicious.
   - The `regex_to_automata.py` script will display the NFA and DFA details for each regex pattern.

## Future Enhancements
- Combine multiple DFAs into a single automaton for efficient multi-pattern matching.
- Extend the system to handle real-time traffic analysis.
- Integrate visualization tools for automata diagrams.

## License
This project is open-source and available under the MIT License.