#!/usr/bin/env python3

import requests
import json
import argparse
import datetime
import re
import time # For potential retry logic if needed

# --- Configuration ---
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b"  # Model used by THIS script for GENERATION
DEFAULT_AUTHOR = "NOVA Generator"
DEFAULT_SEVERITY = "medium" # Default severity for meta section
DEFAULT_SEMANTIC_THRESHOLD = 0.7 # Similarity threshold (0-1) for semantics matching
# LLM Temperature (0-1) for the NOVA *engine* when evaluating the rule's LLM check
DEFAULT_LLM_TEMPERATURE = 0.2
MAX_EXTRACTED_KEYWORDS = 5 # Max number of keywords to extract and use

# --- Helper Function for Ollama Interaction (for Generator Script) ---

def query_ollama(prompt_text, system_message=None):
    """
    Sends a prompt to the local Ollama API (used by this generator script)
    and returns the generated response.

    Args:
        prompt_text (str): The user prompt to send to the LLM.
        system_message (str, optional): An optional system message for the LLM.

    Returns:
        str: The content of the LLM's response, or None if an error occurs.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt_text,
        "stream": False,
        "options": {
             # Use low temp for consistent generation *by this script*
            "temperature": 0.3 # Slightly higher for more creative summarization maybe?
        }
    }
    if system_message:
        payload["system"] = system_message

    print(f"\n🤖 Querying Ollama Generator (Model: {OLLAMA_MODEL})...")
    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=180)
        response.raise_for_status()

        response_data = response.json()
        generated_text = response_data.get('response', '').strip()
        print("✅ Ollama Generator response received.")
        if not generated_text or generated_text.lower() in ["none", "n/a", "[no keywords found]", "[]", "[no semantic phrase]"]:
             print("⚠️ Ollama Generator returned an empty or non-committal response.")
             return None
        return generated_text

    except requests.exceptions.ConnectionError:
        print(f"❌ Error: Could not connect to Ollama API at {OLLAMA_API_URL}.")
        print("Ensure Ollama is running and accessible.")
        return None
    except requests.exceptions.Timeout:
        print("❌ Error: Request to Ollama Generator timed out.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Error interacting with Ollama Generator API: {e}")
        try:
            print(f"   Response Status Code: {response.status_code}")
            print(f"   Response Body: {response.text}")
        except:
            pass
        return None
    except json.JSONDecodeError:
        print(f"❌ Error: Could not decode JSON response from Ollama Generator: {response.text}")
        return None
    except KeyError:
        print(f"❌ Error: Unexpected response format from Ollama Generator: {response_data}")
        return None

# --- Helper to clean and parse keywords ---
def parse_extracted_keywords(text, max_keywords):
    """
    Parses a string potentially containing keywords (comma-separated or newline-separated).

    Args:
        text (str): The text output from Ollama.
        max_keywords (int): The maximum number of keywords to return.

    Returns:
        list[str]: A list of cleaned keywords.
    """
    if not text:
        return []

    # Try splitting by comma first, then newline
    if ',' in text:
        text = text.strip('[]"\' ')
        keywords = text.split(',')
    else:
        keywords = text.splitlines()

    cleaned_keywords = []
    for kw in keywords:
        cleaned = re.sub(r'^[*\-\d\.\s]+', '', kw).strip().strip('"\'')
        if cleaned and len(cleaned) > 2:
            cleaned = cleaned.replace('/', r'\/') # Escape forward slashes
            cleaned_keywords.append(cleaned)

    return cleaned_keywords[:max_keywords]


# --- Core NOVA Rule Generation Logic ---

def generate_nova_rule(user_prompt, author_name, severity, rule_name_prefix="Detect_Prompt"):
    """
    Generates a NOVA rule structure based on the user's input prompt,
    using Ollama to extract keywords and semantic meaning.

    Args:
        user_prompt (str): The prompt provided by the user.
        author_name (str): The name to put in the 'author' meta field.
        severity (str): The severity level for the meta field.
        rule_name_prefix (str): Prefix for the generated rule name.

    Returns:
        str: The formatted NOVA rule string, or None if generation fails.
    """
    print(f"\n📝 Generating NOVA rule for prompt: \"{user_prompt[:100]}...\"")

    # --- Prepare common elements ---
    # Escaped version for NOVA string literals
    escaped_user_prompt_nova = user_prompt.replace('\\', '\\\\').replace('"', '\\"')
    # Generate a unique rule name
    sanitized_prompt_part = re.sub(r'\W+', '_', user_prompt[:30]).strip('_')
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    rule_name = f"{rule_name_prefix}_{sanitized_prompt_part}_{timestamp}"
    rule_name = re.sub(r'^[^a-zA-Z_]+', '', rule_name)
    rule_name = re.sub(r'[^\w]', '', rule_name)
    if not rule_name:
        rule_name = f"{rule_name_prefix}_{timestamp}"

    # --- Meta Section ---
    print("\n📄 Generating Metadata...")
    # 1. Generate Description
    desc_prompt = f"""Analyze the following user prompt and write a concise (1-2 sentence) description for a detection rule. The description should explain that the rule aims to detect this specific prompt, keyword variations, or semantically similar ones.

User Prompt:
\"\"\"
{user_prompt}
\"\"\"

Rule Description:"""
    description = query_ollama(desc_prompt, system_message="You are an assistant security researcher helping create NOVA rules (YARA like but for LLMs prompt detection) descriptions. Keep the description short and do not include any explanation.")
    if description is None:
        print("⚠️ Failed to generate description, using generic one.")
        description = f"Detects prompts similar to the input provided on {datetime.date.today()}."
    description = description.strip().replace('"', '\\"') # Escape quotes

    # --- Keywords Section ---
    print("\n🔑 Generating Keywords...")
    # 2. Define Exact Keyword
    keyword_exact_line = f'        $prompt_exact = "{escaped_user_prompt_nova}"'
    keyword_exact_var = "keywords.$prompt_exact"

    # 3. Extract Keywords using Ollama
    keyword_extraction_prompt = f"""Analyze the following user prompt and identify up to {MAX_EXTRACTED_KEYWORDS} distinct, important keywords or short keyphrases (2-3 words max). These should help identify prompts on the same topic.

User Prompt:
\"\"\"
{user_prompt}
\"\"\"

List the keywords/keyphrases, separated by commas. Output only the comma-separated list:"""
    extracted_keywords_raw = query_ollama(
        keyword_extraction_prompt,
        system_message=f"You are an AI security researcher assistant that extracts keywords. Respond ONLY with a comma-separated list of up to {MAX_EXTRACTED_KEYWORDS} items. No explanations."
    )

    extracted_keywords = []
    keyword_regex_lines = []
    keyword_regex_vars = [] # Store variable names like keywords.$keyword_1

    if extracted_keywords_raw:
        extracted_keywords = parse_extracted_keywords(extracted_keywords_raw, MAX_EXTRACTED_KEYWORDS)
        if extracted_keywords:
            print(f"  Extracted keywords: {extracted_keywords}")
            for i, kw in enumerate(extracted_keywords):
                var_name = f"$keyword_{i+1}"
                keyword_regex_lines.append(f'        {var_name} = /{kw}/i')
                keyword_regex_vars.append(f"keywords.{var_name}")
        else:
            print("  ⚠️ Could not parse keywords from Ollama response.")
    else:
        print("  ⚠️ Failed to extract keywords using Ollama.")

    keywords_block = keyword_exact_line
    if keyword_regex_lines:
        keywords_block += "\n" + "\n".join(keyword_regex_lines)

    # --- Semantics Section ---
    print("\n🧠 Generating Semantics...")
    # 4. Extract Semantic Phrase using Ollama
    semantic_extraction_prompt = f"""Analyze the following user prompt and summarize its core semantic meaning or intent into a concise phrase (ideally 3-7 words). This phrase should capture the essence of what the user is asking for or trying to achieve.

User Prompt:
\"\"\"
{user_prompt}
\"\"\"

Concise Semantic Phrase:"""
    semantic_phrase = query_ollama(
        semantic_extraction_prompt,
        system_message="You are an AI security researcher assistant that summarizes prompt intent into short phrases. Output ONLY the phrase."
    )

    semantic_pattern_line = ""
    semantic_var = None # Variable name for condition

    if semantic_phrase:
        # Clean and escape the generated phrase
        semantic_phrase = semantic_phrase.strip().strip('.').replace('"', '\\"').replace('\\', '\\\\')
        print(f"  Generated semantic phrase: \"{semantic_phrase}\"")
        # Use the generated phrase in the semantics section
        semantic_pattern_line = f'        $extracted_semantic = "{semantic_phrase}" ({DEFAULT_SEMANTIC_THRESHOLD})'
        semantic_var = "semantics.$extracted_semantic"
    else:
        print("  ⚠️ Failed to generate semantic phrase. Falling back to using the full prompt.")
        # Fallback: Use the original prompt if generation fails
        semantic_pattern_line = f'        $prompt_semantic_fallback = "{escaped_user_prompt_nova}" ({DEFAULT_SEMANTIC_THRESHOLD})'
        semantic_var = "semantics.$prompt_semantic_fallback"

    # --- LLM Section ---
    print("\n🤖 Generating LLM Check Instruction...")
    # 5. Generate LLM Check Instruction using Ollama
    llm_check_gen_prompt = f"""Given the following user prompt:
\"\"\"
{user_prompt}
\"\"\"

Create a concise instruction prompt for a powerful AI security model (acting as a judge). This instruction should ask the judge model to evaluate whether a *different*, new prompt it receives has the same harmful intent, malicious goal, or seeks the same sensitive information/action as the original prompt shown above. The instruction should clearly state the evaluation task. Focus on the core objective.

Instruction Prompt for Judge Model:"""
    llm_check_prompt_text = query_ollama(
        llm_check_gen_prompt,
        system_message="You create concise instruction prompts for AI security evaluation models."
    )

    llm_check_line = ""
    llm_var = None # Variable name for condition

    if llm_check_prompt_text:
        # Clean and escape
        llm_check_prompt_text = llm_check_prompt_text.strip().replace('"', '\\"').replace('\\', '\\\\')
        print(f"  Generated LLM check instruction: \"{llm_check_prompt_text[:100]}...\"")
        llm_check_line = f'        $llm_intent_check = "{llm_check_prompt_text}" ({DEFAULT_LLM_TEMPERATURE})'
        llm_var = "llm.$llm_intent_check"
    else:
        print("  ⚠️ Failed to generate LLM check instruction.")
        # Decide if fallback is needed or omit LLM check? Omit for now if generation fails.
        # llm_check_line = f'# LLM check generation failed'

    # --- Condition Section ---
    print("\n⚙️ Assembling Condition...")
    # 6. Define Condition
    condition_parts = []
    condition_parts.append(keyword_exact_var) # Exact keyword match
    condition_parts.extend(keyword_regex_vars) # Extracted regex keywords
    if semantic_var:
        condition_parts.append(semantic_var) # Semantic match (using generated phrase or fallback)
    if llm_var:
        condition_parts.append(llm_var) # LLM check

    if not condition_parts:
         print("❌ ERROR: No valid detection elements (keywords, semantics, llm) were generated. Cannot create condition.")
         return None # Cannot create a rule without a condition

    # Build the final condition string
    condition = "\n        " + " or\n        ".join(condition_parts) # Format for readability
    print(f"  Condition built: {condition.strip()}")

    # --- Assemble Final Rule ---
    print("\n🏁 Finalizing NOVA Rule...")
    nova_rule = f"""\
rule {rule_name} {{
    meta:
        description = "{description}"
        author = "{author_name}"
        severity = "{severity}"
        created = "{datetime.datetime.now().isoformat()}"
        source_prompt_hash = "{hash(user_prompt)}" // Hash of original prompt

    keywords:
{keywords_block}

    semantics:
{semantic_pattern_line}

    llm:
{llm_check_line if llm_check_line else '        # LLM check generation failed or was omitted'}

    condition:
{condition}
}}"""

    print("✅ NOVA rule generated successfully.")
    return nova_rule

# --- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NOVA Generator: Creates a NOVA rule to detect a specific user prompt using a local Ollama instance.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    # Add arguments (prompt, author, severity, output, model, api-url, max-keywords, semantic-threshold, llm-temperature)
    parser.add_argument(
        "-p", "--prompt", required=True,
        help="The user prompt text for rule generation."
    )
    parser.add_argument(
        "-a", "--author", default=DEFAULT_AUTHOR,
        help="Author name for rule metadata."
    )
    parser.add_argument(
        "-s", "--severity", default=DEFAULT_SEVERITY,
        choices=['low', 'medium', 'high', 'critical', 'info'],
        help="Severity level for rule metadata."
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional file path to save the generated rule."
    )
    parser.add_argument(
        "--model", default=OLLAMA_MODEL,
        help="Ollama model for THIS SCRIPT to use for generation."
    )
    parser.add_argument(
        "--api-url", default=OLLAMA_API_URL,
        help="Ollama API endpoint URL for this script."
    )
    parser.add_argument(
        "--max-keywords", type=int, default=MAX_EXTRACTED_KEYWORDS,
        help="Maximum number of keywords to extract."
    )
    parser.add_argument(
        "--semantic-threshold", type=float, default=DEFAULT_SEMANTIC_THRESHOLD,
        help="Similarity threshold (0.0-1.0) for the 'semantics' section."
    )
    parser.add_argument(
        "--llm-temperature", type=float, default=DEFAULT_LLM_TEMPERATURE,
        help="Temperature (0.0-1.0) for 'llm' evaluation by the NOVA engine."
    )

    args = parser.parse_args()

    # Update global config from command-line args
    OLLAMA_MODEL = args.model
    OLLAMA_API_URL = args.api_url
    MAX_EXTRACTED_KEYWORDS = args.max_keywords
    DEFAULT_SEMANTIC_THRESHOLD = args.semantic_threshold
    DEFAULT_LLM_TEMPERATURE = args.llm_temperature

    # Get current time and location
    current_time_iso = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()
    current_location = "Prague, Prague, Czechia" # From context

    print("--- NOVA Generator ---")
    print(f"Timestamp: {current_time_iso}")
    print(f"Location: {current_location}")
    print(f"Using Ollama Model for Generation: {OLLAMA_MODEL}")
    print(f"Semantic Threshold for Rule: {DEFAULT_SEMANTIC_THRESHOLD}")
    print(f"LLM Temperature for Rule: {DEFAULT_LLM_TEMPERATURE}")


    # Generate the rule
    generated_rule = generate_nova_rule(
        user_prompt=args.prompt,
        author_name=args.author,
        severity=args.severity
    )

    if generated_rule:
        print("\n--- Generated NOVA Rule ---")
        print(generated_rule)
        print("-------------------------\n")

        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(generated_rule)
                print(f"✅ Rule successfully saved to: {args.output}")
            except IOError as e:
                print(f"❌ Error writing rule to file {args.output}: {e}")
        else:
            print("ℹ️  Use the --output flag to save the rule to a file.")
    else:
        print("\n❌ Failed to generate NOVA rule.")

    print("--- Generator Finished ---")