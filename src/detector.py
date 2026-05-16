from sentence_transformers import SentenceTransformer, util
from colorama import Fore
import re

model = SentenceTransformer('all-MiniLM-L6-v2')

template_embeddings = None

# Load templates dynamically from main.py
def load_templates(template_list):
    global template_embeddings
    
    if not template_list:
        template_embeddings = None
        return
    
    template_embeddings = model.encode(template_list, convert_to_tensor=True)


#L1
KEYWORD_GROUPS = {
    "instruction_override": {
        "words": ["ignore", "override", "disregard", "bypass", "skip"],
        "weight": 3
    },
    "data_exfiltration": {
        "words": ["reveal", "extract", "display"],
        "weight": 4
    },
    "sensitive_context": {
        "words": [ "system",
        "prompt",
        "config",
        "hidden",
        "internal",
        "password",
        "passwords",
        "credentials",
        "admin",
        "token",
        "api key"],
        "weight": 3
    }
}

#L2
PATTERNS = {
    r".*admin credentials": 5,
    r"give me.*credentials": 5,
    r"reveal.*password": 5,
    r"give.*admin access": 5,
    r"give me.*password": 5,
    r"show.*password": 5,
    r"reveal.*credentials": 5
}



def semantic_score(prompt):
    if template_embeddings is None:
        return 0
    
    prompt_embedding = model.encode(prompt, convert_to_tensor=True)
    scores = util.cos_sim(prompt_embedding, template_embeddings)
    
    return scores.max().item()


# 🔹 Main Detection Function
def detect_prompt(prompt):
    prompt_lower = prompt.lower()
    attack_types = set()
    score = 0
    reasons = []

    #Keyword Detection
    for category, data in KEYWORD_GROUPS.items():
        for word in data["words"]:
            if re.search(rf"\b{word}\b", prompt_lower):
                score += data["weight"]
                reasons.append(f"{category} keyword: {word}")
                attack_types.add(category)

    #Pattern Matching
    for pattern, weight in PATTERNS.items():
        if re.search(pattern,prompt_lower):
            score += weight
            reasons.append(f"Pattern match: {pattern}")
            attack_types.add("pattern_attack")

   #Intent-Based Logic
    if ("ignore" in prompt_lower or "disregard" in prompt_lower) and ("instruction" in prompt_lower or "rules" in prompt_lower):
        score += 3
        reasons.append("Intent: instruction override")
        attack_types.add("instruction_override")

    if ("system" in prompt_lower or "internal" in prompt_lower) and ("prompt" in prompt_lower or "config" in prompt_lower):
        score += 3
        reasons.append("Intent: sensitive data access")
        attack_types.add("sensitive_access")
    if("password" in prompt_lower or "passwords" in prompt_lower or "credentials" in prompt_lower or "admin" in prompt_lower or "token" in prompt_lower):
        score+= 4
        reasons.append("Intent: credential or privileged access")
        attack_types.add("credential_Access")


    #Semantic Similarity
    sim = semantic_score(prompt)

    if sim > 0.30:
        score += 8
        reasons.append(f"Semantic similarity: {round(sim, 2)}")


 # 🔹 Informational Intent Reduction
    informational_words = ["what", "when", "how", "who", "why", "explain","define", "describe", "discuss", "tell me"]
    if any(prompt_lower.startswith(word) for word in informational_words):
            score -= 2
            reasons.append("Informational query detected")


    # 🔹 Prevent negative scores
    score = max(score, 0)
        
    if score >= 3.5:
        label = "ATTACK"
        color = Fore.RED
    else:
        label = "SAFE"
        color = Fore.GREEN
    
    if score>=8:
        confidence = "High"

    elif score >=5:
        confidence = "Medium"
    else:
        confidence = "Low"

    return {
        "label": label,
        "score": score,
        "reasons": reasons,
        "color": color,
        "attack_types":list(attack_types),
        "confidence":confidence
    }
    