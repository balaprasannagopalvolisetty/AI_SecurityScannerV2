#!/bin/bash

# Advanced Web Security Scanner Installation Script
echo "Installing Advanced Web Security Scanner..."

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>&1 | awk '{print $2}')
if [[ -z "$python_version" ]]; then
    echo "Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Create a virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install required Python packages
echo "Installing required Python packages..."
pip install fastapi uvicorn aiohttp beautifulsoup4 python-whois dnspython requests pydantic

# Clone required repositories
echo "Cloning required repositories..."
if [ ! -d "PayloadsAllTheThings" ]; then
    git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
fi

if [ ! -d "cvelistV5" ]; then
    git clone https://github.com/CVEProject/cvelistV5.git
fi

# Check if Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo "Ollama is not installed. Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
fi

# Pull the Ollama model
echo "Pulling the Ollama model..."
ollama_model=${OLLAMA_MODEL:-"ALIENTELLIGENCE/predictivethreatdetection"}
ollama pull $ollama_model

# Create a .env file for API keys
echo "Creating .env file..."
cat > .env << EOL
SHODAN_API_KEY=${SHODAN_API_KEY:-""}
VT_API_KEY=${VT_API_KEY:-""}
NVD_API_KEY=${NVD_API_KEY:-""}
OPENAI_API_KEY=${OPENAI_API_KEY:-""}
OLLAMA_MODEL=${OLLAMA_MODEL:-"ALIENTELLIGENCE/predictivethreatdetection"}
EOL

# Create modules directory if it doesn't exist
mkdir -p modules

# Create a run script
echo "Creating run script..."
cat > run.sh << EOL
#!/bin/bash
source venv/bin/activate
source .env
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
EOL
chmod +x run.sh

echo "Installation complete!"
echo "To start the application, run: ./run.sh"

