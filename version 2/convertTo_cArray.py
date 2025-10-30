import numpy as np

# Load TFLite model
with open("esp32_attack_model_optimized.tflite", "rb") as f:
    tflite_model = f.read()

# Convert to a C-style array
c_array = ', '.join(f'0x{b:02x}' for b in tflite_model)

# Format C array output
c_code = f"""
#include <stddef.h>

const unsigned char model_tflite[] = {{
    {c_array}
}};
const size_t model_tflite_len = {len(tflite_model)};
"""

# Save to a file
with open("model_data.cc", "w") as f:
    f.write(c_code)

print("\n✅ TFLite model successfully converted to C array and saved as model_data.cc")
