"""
export_model.py
===============
Exports the ML Guard model to ONNX format for fast CPU inference.

Usage:
    pip install torch onnx onnxscript transformers
    python export_model.py

Output:
    models/ml_guard.onnx       (~780KB graph)
    models/ml_guard.onnx.data  (~256MB weights)
"""

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from pathlib import Path

MODEL_NAME = "distilbert-base-uncased-finetuned-sst-2-english"
OUTPUT_DIR = Path("models")
OUTPUT_PATH = OUTPUT_DIR / "ml_guard.onnx"


def main():
    print(f"[1/4] Downloading model: {MODEL_NAME}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    model.eval()

    print("[2/4] Creating dummy input")
    dummy = tokenizer("test injection attempt", return_tensors="pt", padding=True, truncation=True)

    print("[3/4] Creating output directory")
    OUTPUT_DIR.mkdir(exist_ok=True)

    print(f"[4/4] Exporting to ONNX: {OUTPUT_PATH}")
    torch.onnx.export(
        model,
        (dummy["input_ids"], dummy["attention_mask"]),
        str(OUTPUT_PATH),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids":      {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits":         {0: "batch"},
        },
        opset_version=14,
    )
    print(f"✓ Done — {OUTPUT_PATH} created ({OUTPUT_PATH.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
