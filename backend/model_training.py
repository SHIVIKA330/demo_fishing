import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix, roc_auc_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import StandardScaler
import pickle
import warnings
import time
warnings.filterwarnings('ignore')

# --- 1. Load the Feature-Extracted Data ---
print("Loading feature data...")
try:
    df = pd.read_csv('phishing_features.csv')
    print(f"Dataset shape: {df.shape}")
    
    if df.isnull().sum().sum() > 0:
        print("Handling missing values...")
        df = df.fillna(0)
        
except FileNotFoundError:
    print("Error: 'phishing_features.csv' not found. Please run feature_extraction.py first.")
    exit()

# --- 2. Separate Features (X) and Labels (y) ---
X = df.drop('Label', axis=1)
y = df['Label']
print(f"Features shape: {X.shape}, Labels shape: {y.shape}")

# --- 3. Scale Features ---
print("Scaling features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# --- 4. Split the Data ---
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Training set: {X_train.shape}, Test set: {X_test.shape}")

# --- 5. Train Multiple Models ---
print("Training models...")

models = {
    'XGBoost': XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        eval_metric='logloss',
        scale_pos_weight=1  # Adjust if dataset is imbalanced
    ),
    'RandomForest': RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    ),
    'LightGBM': LGBMClassifier(
        n_estimators=200,
        max_depth=10,
        learning_rate=0.1,
        random_state=42,
        n_jobs=-1,
        verbose=-1,
        is_unbalance=True
    )
}

best_model = None
best_score = 0
best_model_name = ""

# Use smaller CV for speed
cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

for name, model in models.items():
    print(f"\n--- Training {name} ---")
    start_time = time.time()
    
    # Train on full training set
    model.fit(X_train, y_train)
    training_time = time.time() - start_time
    
    # Test set performance
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    test_accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc_score = roc_auc_score(y_test, y_pred_proba)
    
    print(f"Training time: {training_time:.2f} seconds")
    print(f"Accuracy: {test_accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score: {f1:.4f}")
    print(f"AUC Score: {auc_score:.4f}")
    
    # Use F1-score as primary metric (balances precision and recall)
    if f1 > best_score:
        best_score = f1
        best_model = model
        best_model_name = name

# --- 6. Final Evaluation of Best Model ---
print(f"\n=== Best Model: {best_model_name} ===")
y_pred = best_model.predict(X_test)
y_pred_proba = best_model.predict_proba(X_test)[:, 1]

print("\nDetailed Classification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Calculate additional metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_pred_proba)

print(f"\nFinal Model Performance:")
print(f"Accuracy: {accuracy * 100:.2f}%")
print(f"Precision: {precision * 100:.2f}%")
print(f"Recall: {recall * 100:.2f}%")
print(f"F1-Score: {f1 * 100:.2f}%")
print(f"AUC Score: {auc:.4f}")

# --- 7. Feature Importance ---
if hasattr(best_model, 'feature_importances_'):
    print("\nTop 15 Most Important Features:")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': best_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(feature_importance.head(15))

# --- 8. Save the Trained Model and Scaler ---
model_filename = 'phishing_model.pkl'
scaler_filename = 'scaler.pkl'

with open(model_filename, 'wb') as file:
    pickle.dump(best_model, file)

with open(scaler_filename, 'wb') as file:
    pickle.dump(scaler, file)

print(f"\n✓ Trained model saved to '{model_filename}'")
print(f"✓ Scaler saved to '{scaler_filename}'")
print(f"✓ Best model: {best_model_name} with F1-score: {f1 * 100:.2f}%")

# --- 9. Save feature names for reference ---
feature_names = list(X.columns)
with open('feature_names.pkl', 'wb') as f:
    pickle.dump(feature_names, f)
print(f"✓ Feature names saved to 'feature_names.pkl'")