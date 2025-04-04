import argparse
import os

def tflite_to_c_array(input_path, output_path):
    with open(input_path, "rb") as f:
        model_data = f.read()
    
    array_name = os.path.splitext(os.path.basename(input_path))[0]
    header_guard = f"{array_name.upper()}_H"
    
    with open(output_path, "w") as f:
        f.write(f"#ifndef {header_guard}\n#define {header_guard}\n\n")
        f.write("#include <stdint.h>\n\n")
        f.write(f"const unsigned char {array_name}[] = {{\n")
        
        for i, byte in enumerate(model_data):
            if i % 12 == 0:
                f.write("    ")
            f.write(f"0x{byte:02X}, ")
            if (i + 1) % 12 == 0 or (i + 1) == len(model_data):
                f.write("\n")
        
        f.write("};\n\n")
        f.write(f"const unsigned int {array_name}_len = {len(model_data)};\n\n")
        f.write(f"#endif // {header_guard}\n")
    
    print(f"Converted {input_path} to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert a TFLite model to a C array.")
    parser.add_argument("input", nargs='?', default=r"C:\\Users\\dexterGT\\Desktop\\ECE TEJESWAR G\\Devhouse hackathon\\esp32_attack_model_optimized.tflite", help="Path to the TFLite model file")
    parser.add_argument("output", nargs='?', default=r"C:\\Users\\dexterGT\\Desktop\\ECE TEJESWAR G\\Devhouse hackathon\\esp32_attack_model_optimized.h", help="Path to the output C header file")
    args = parser.parse_args()
    
    tflite_to_c_array(args.input, args.output)