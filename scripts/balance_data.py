# scripts/balance_data.py

import os
import pandas as pd
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE

# ──────────────────────────────────────────────────────────────
# 1. CONFIGURATION
# Paths to cleaned CSVs and output folder
# ──────────────────────────────────────────────────────────────
PHISH_CSV = "data/raw/phish.csv"
LEGIT_CSV = "data/raw/legit.csv"
OUTPUT_DIR = "data/processed"
TRAIN_CSV = os.path.join(OUTPUT_DIR, "train.csv")
HOLDOUT_CSV = os.path.join(OUTPUT_DIR, "holdout.csv")

# Desired ratio: 1 phish : N legit
LEGIT_RATIO = 2

# Whether to perform SMOTE oversampling on phish class (set False to skip)
USE_SMOTE = False

# ──────────────────────────────────────────────────────────────
# 2. LOAD DATA
# ──────────────────────────────────────────────────────────────
print("Loading cleaned data...")
phish = pd.read_csv(PHISH_CSV)
legit = pd.read_csv(LEGIT_CSV)
print(f"  Phish: {len(phish)} rows")
print(f"  Legit: {len(legit)} rows\n")

# ──────────────────────────────────────────────────────────────
# 3. UNDERSAMPLE LEGITIMATE CLASS
# Undersampling: Reduces the larger class (legit) to avoid bias.
# ──────────────────────────────────────────────────────────────
desired_legit_n = len(phish) * LEGIT_RATIO
actual_legit_n = min(desired_legit_n, len(legit))
if desired_legit_n > len(legit):
    print(
        f"⚠️ Requested {desired_legit_n} legit URLs, but only {len(legit)} available. "
        f"Capping to {actual_legit_n}."
    )
legit_sampled = legit.sample(n=actual_legit_n, random_state=42)

print(f"Undersampled legit from {len(legit)} to {len(legit_sampled)} rows\n")

# ──────────────────────────────────────────────────────────────
# 4. OPTIONAL: SMOTE OVERSAMPLING
# Note: SMOTE requires numeric features. If you haven’t extracted features
# yet, keep USE_SMOTE=False. Once you have a feature matrix X, you can
# apply SMOTE on X and y here instead of on raw URLs.
# ──────────────────────────────────────────────────────────────
# !to understand later: SMOTE (Synthetic Minority Over-sampling Technique)
# is a technique to create synthetic samples for the minority class
# to balance class distribution in datasets, particularly useful for imbalanced datasets.

if USE_SMOTE:
    print("Applying SMOTE to oversample phish class...")
    # Placeholder: In practice, extract numeric features first!
    from sklearn.feature_extraction.text import CountVectorizer

    # Example: vectorize URL strings into simple token counts
    vect = CountVectorizer(analyzer="char_wb", ngram_range=(3, 5))
    X = vect.fit_transform(pd.concat([phish["url"], legit_sampled["url"]]))
    y = pd.concat([phish["label"], legit_sampled["label"]])

    sm = SMOTE(random_state=42)
    X_res, y_res = sm.fit_resample(X, y)

    # Convert back to DataFrame (URLs would need mapping; here just logging)
    print(f"  SMOTE produced {len(y_res)} total samples\n")
    # You would reconstruct `phish` and `legit_sampled` DataFrames from X_res/y_res here.

# ──────────────────────────────────────────────────────────────
# 5. MERGE, SHUFFLE & SPLIT
# ──────────────────────────────────────────────────────────────
balanced = pd.concat([phish, legit_sampled], ignore_index=True)
# Shuffle rows
balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

# Split out 5% hold-out
train_df, holdout_df = train_test_split(
    balanced, test_size=0.05, stratify=balanced["label"], random_state=42
)

print(f"Final counts:")
print(f"  Training set: {len(train_df)} rows")
print(f"  Hold-out set: {len(holdout_df)} rows\n")

# ──────────────────────────────────────────────────────────────
# 6. SAVE OUTPUTS
# ──────────────────────────────────────────────────────────────
os.makedirs(OUTPUT_DIR, exist_ok=True)
train_df.to_csv(TRAIN_CSV, index=False)
holdout_df.to_csv(HOLDOUT_CSV, index=False)
print(f"✔ Saved train to {TRAIN_CSV}")
print(f"✔ Saved holdout to {HOLDOUT_CSV}")
