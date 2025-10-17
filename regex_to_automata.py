# Conversion of Regex to NFA and DFA
from automata.fa.dfa import DFA
from automata.fa.nfa import NFA
from automata.regex.parser import parse_regex
import csv

def load_dataset(file_path):
    """Load SQL queries from a CSV file."""
    queries = []
    try:
        with open(file_path, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row if present
            for row in reader:
                queries.append(row[0])  # Assuming the first column contains the SQL queries
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    return queries

def regex_to_nfa(pattern):
    """Convert regex to NFA."""
    return parse_regex(pattern).to_nfa()

def nfa_to_dfa(nfa):
    """Convert NFA to DFA."""
    return DFA.from_nfa(nfa)

def display_automata(automata, automata_type):
    """Display details of NFA or DFA."""
    print(f"{automata_type} States:", automata.states)
    print(f"{automata_type} Alphabet:", automata.input_symbols)
    print(f"{automata_type} Transitions:", automata.transitions)
    print(f"{automata_type} Start State:", automata.initial_state)
    print(f"{automata_type} Accept States:", automata.final_states)
    print("\n")

def main():
    print("Regex to Automata Conversion\n")

    # Define regex patterns
    patterns = {
        "SQL Injection": r"(\'|\")\s*OR\s*1\s*=\s*1|UNION\s+SELECT|--|;|DROP\s+TABLE|INSERT\s+INTO|xp_cmdshell",
        "XSS": r"<script>.*</script>|<.*on\w+=.*>|javascript:.*|<iframe.*>|<img.*src=.*>",
        "Command Injection": r"(\;|\&|\|)\s*(rm|cat|bash|sh|wget|curl|scp|nc|netcat|python|perl|php|ruby|java|gcc|g\+\+|make)"
    }

    for name, pattern in patterns.items():
        print(f"Pattern: {name}")
        nfa = regex_to_nfa(pattern)
        print("NFA Details:")
        display_automata(nfa, "NFA")

        dfa = nfa_to_dfa(nfa)
        print("DFA Details:")
        display_automata(dfa, "DFA")

    # Load dataset
    dataset_path = "d:\\TOC\\intrusion_detection_system\\sql_queries.csv"  # Example dataset path
    inputs = load_dataset(dataset_path)

    if not inputs:
        print("No queries to process. Please check the dataset file.")
        return

    print("Processing SQL Queries:\n")
    for i, query in enumerate(inputs, start=1):
        print(f"Query {i}: {query}")

if __name__ == "__main__":
    main()