#!/bin/bash
# Setup script for Cybersecurity News Agent API key

echo "================================================"
echo "  Cybersecurity News Agent - API Key Setup"
echo "================================================"
echo ""
echo "Please enter your Anthropic API key:"
echo "(It will not be displayed on screen)"
echo ""
read -s ANTHROPIC_API_KEY

if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "Error: No API key provided"
    exit 1
fi

echo ""
echo "Configuring API key..."

# Add to .zshrc if not already there
if ! grep -q "ANTHROPIC_API_KEY" ~/.zshrc 2>/dev/null; then
    echo "" >> ~/.zshrc
    echo "# Anthropic API Key for Cyber News Agent" >> ~/.zshrc
    echo "export ANTHROPIC_API_KEY=\"$ANTHROPIC_API_KEY\"" >> ~/.zshrc
    echo "✓ Added to ~/.zshrc"
else
    echo "! API key already exists in ~/.zshrc - skipping"
fi

# Update launchd plist with API key
PLIST_PATH=~/Library/LaunchAgents/com.cybernews.agent.plist

# Create backup
cp "$PLIST_PATH" "${PLIST_PATH}.backup"

# Update the plist to include ANTHROPIC_API_KEY
/usr/libexec/PlistBuddy -c "Set :EnvironmentVariables:ANTHROPIC_API_KEY $ANTHROPIC_API_KEY" "$PLIST_PATH" 2>/dev/null

if [ $? -ne 0 ]; then
    # Key doesn't exist, add it
    /usr/libexec/PlistBuddy -c "Add :EnvironmentVariables:ANTHROPIC_API_KEY string $ANTHROPIC_API_KEY" "$PLIST_PATH"
fi

echo "✓ Updated launchd plist with API key"

echo ""
echo "================================================"
echo "  Configuration Complete!"
echo "================================================"
echo ""
echo "Your API key has been securely configured."
echo "To apply changes to your current terminal:"
echo "  source ~/.zshrc"
echo ""
echo "The scheduled task will use the API key automatically."
echo ""
