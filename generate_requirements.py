import os
import subprocess

def generate_requirements():
    try:
        # Use pip freeze to list all installed packages
        result = subprocess.run(['pip', 'freeze'], capture_output=True, text=True, check=True)
        requirements = result.stdout

        # Save to requirements.txt
        with open('requirements.txt', 'w') as f:
            f.write(requirements)

        print("✅ requirements.txt generated successfully!")
    except Exception as e:
        print(f"❌ Failed to generate requirements.txt: {e}")

if __name__ == '__main__':
    generate_requirements()
