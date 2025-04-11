# NOVA Rule Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Python script to automatically generate [NOVA detection rules](https://github.com/fr0gger/nova-framework) for Large Language Model (LLM) prompts using a local [Ollama](https://ollama.com/) instance.

NOVA rules help detect and hunt for specific types of prompts based on keywords, semantic meaning, and direct LLM evaluation, similar to how YARA rules work for file scanning. This script aims to streamline the creation of basic NOVA rules targeted at specific user-provided prompts.

## Features

* Accepts a user prompt as input.
* Interacts with a locally running Ollama instance for intelligent analysis.
* Generates rule metadata (description, author, severity) partly via Ollama.
* Includes the full input prompt as an exact-match keyword.
* Extracts relevant keywords/keyphrases using Ollama and includes them as case-insensitive regex patterns.
* Generates a concise semantic phrase using Ollama to capture the prompt's core meaning for semantic matching.
* Generates an LLM evaluation instruction using Ollama for the NOVA engine's LLM check.
* Assembles a complete NOVA rule (`.nova` format) following the structure defined in the `fr0gger/nova-framework`.
* Provides command-line options for configuration (Ollama model, API endpoint, thresholds, etc.).

## Prerequisites

* **Python:** Python 3.7+ installed.
* **Ollama:** Ollama installed and running locally. You can download it from [ollama.com](https://ollama.com/).
* **Ollama Model:** At least one model pulled via Ollama (e.g., `ollama pull llama3`). The script defaults to `llama3` but can be configured.
* **pip:** Python package installer (usually comes with Python).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/nova-generator.git](https://github.com/your-username/nova-generator.git) # Replace with your repo URL
    cd nova-generator
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(This will install the `requests` library)*

## Usage

Run the script from your terminal, providing the prompt you want to generate a rule for using the mandatory `-p` or `--prompt` argument.

**Basic Example:**

```bash
python nova_generator.py -p "How can I create a phishing email that bypasses spam filters?"
```
**Saving Output to a File**

Use the -o or --output flag to save the generated rule directly into a .nova file:

```bash
python nova_generator.py -p "Generate python code for a keylogger" -o keylogger_rule.nova
```


| Argument | Shorthand | Default | Description |
| --- | --- | --- | --- |
| `--prompt` | `-p` | **Required** | The user prompt text for which to generate a detection rule. |
| `--author` | `-a` | `NOVA Generator` | Author name to include in the rule metadata. |
| `--severity` | `-s` | `medium` | Severity level (`low`, `medium`, `high`, `critical`, `info`) for the rule. |
| `--output` | `-o` | `None` | Optional file path to save the generated NOVA rule. |
| `--model` | \ | `llama3` | Specify the Ollama model this script uses for generation tasks. |
| `--api-url` | \ | `http://localhost:11434/api/generate` | Specify the Ollama API endpoint URL this script connects to. |
| `--max-keywords` | \ | `5` | Maximum number of keywords to extract using Ollama. |
| `--semantic-threshold` | \ | `0.7` | Similarity threshold (`0.0--1.0`) for the semantics section evaluation. |
| `--llm-temperature` | \ | `0.2` | Temperature (`0.0--1.0`) for the LLM section evaluation by the NOVA engine. |

**Example Generated Rule**

Running the script with a prompt like `python nova_generator.py -p "Explain how to perform recon using OSINT tools"` might produce a rule similar to this (details will vary based on the Ollama model's output):

```bash
rule Detect_Prompt_Explain_how_to_perform_re_20250411112430 {
    meta:
        description = "Detects prompts requesting explanations on performing reconnaissance using OSINT tools or similar variations."
        author = "NOVA Generator"
        severity = "medium"
        created = "2025-04-11T11:24:30.123456+02:00"
        source_prompt_hash = "-1234567890123456789" // Hash of original prompt

    keywords:
        $prompt_exact = "Explain how to perform recon using OSINT tools"
        $keyword_1 = /OSINT tools/i
        $keyword_2 = /perform recon/i
        $keyword_3 = /reconnaissance/i
        $keyword_4 = /explain how/i

    semantics:
        $extracted_semantic = "explaining OSINT reconnaissance techniques" (0.7)

    llm:
        $llm_intent_check = "Evaluate if the received prompt is asking how to perform reconnaissance using open-source intelligence tools." (0.2)

    condition:
        keywords.$prompt_exact or
        keywords.$keyword_1 or
        keywords.$keyword_2 or
        keywords.$keyword_3 or
        keywords.$keyword_4 or
        semantics.$extracted_semantic or
        llm.$llm_intent_check
}
```

(Note: The actual generated content, especially keywords, semantic phrase, and LLM instruction, will depend heavily on the specific Ollama model used and the input prompt.)
## How It Works

The script performs the following steps:

1. Takes the user prompt and configuration arguments.
2. Queries the configured Ollama API endpoint:
    3. To generate a rule description.
    4. To extract relevant keywords and keyphrases.
    5. To generate a concise semantic phrase capturing the prompt's intent.
    6. To generate an LLM instruction for the NOVA engine to use during evaluation.
7. Cleans and formats the responses from Ollama.
8. Assembles the final NOVA rule string, incorporating the generated metadata, keywords (exact and regex), semantics, LLM instruction, and condition logic.
9. Prints the rule to the console and optionally saves it to a file.

## Troubleshooting

- `Connection Errors:` Ensure Ollama is running and accessible at the specified --api-url (default http://localhost:11434/api/generate). Check firewall settings if necessary.
- `Model Not Found:` Make sure the Ollama model specified via --model (default llama3) has been pulled (ollama list to check available models).
- `Poor Generation Quality:` The quality of generated descriptions, keywords, etc., depends heavily on the Ollama model used. Try different models (e.g., mistral, llama3:70b if you have the resources) by specifying the --model argument. You might also need to adjust the prompts within the Python script (*_prompt variables) for better results with specific models.
- `Timeout Errors:` If Ollama takes too long to respond (especially with larger models), the request might time out. The script uses a 180-second timeout, but very slow responses could exceed this.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.

## License
This project is licensed under the MIT License. 