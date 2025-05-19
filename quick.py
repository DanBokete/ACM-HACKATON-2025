import json

# Load your original dictionary
with open("country.json", "r", encoding="utf-8") as f:
    alpha2_to_country = json.load(f)

# Flip the dictionary
country_to_alpha2 = {v: k for k, v in alpha2_to_country.items()}

# Save the flipped dictionary
with open("countries.json", "w", encoding="utf-8") as f:
    json.dump(country_to_alpha2, f, ensure_ascii=False, indent=2)
