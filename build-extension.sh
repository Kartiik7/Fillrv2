#!/bin/bash
# Fillr Extension Builder v2.0
# Creates fillr-extension-v2.0.0-beta.zip for distribution

echo ""
echo -e "\033[1;36m🔧 Building Fillr Extension Package...\033[0m"

# Set paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTENSION_PATH="$SCRIPT_DIR/extension"
OUTPUT_ZIP="$SCRIPT_DIR/fillr-extension-v2.0.0-beta.zip"

# Remove old ZIP if exists
if [ -f "$OUTPUT_ZIP" ]; then
    rm -f "$OUTPUT_ZIP"
    echo -e "\033[1;33m🗑️  Removed old package\033[0m"
fi

# Required files
FILES_TO_PACKAGE=(
    "manifest.json"
    "background.js"
    "content.js"
    "matcher.js"
    "popup.html"
    "popup.js"
    "styles.css"
    "env.js"
    "icons"
)

# Verify all required files exist
MISSING_FILES=()
for file in "${FILES_TO_PACKAGE[@]}"; do
    if [ ! -e "$EXTENSION_PATH/$file" ]; then
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo -e "\033[1;31m❌ Missing required files:\033[0m"
    for file in "${MISSING_FILES[@]}"; do
        echo -e "   - $file"
    done
    exit 1
fi

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Copy files to temp directory
echo -e "\033[1;32m📦 Copying extension files...\033[0m"
for file in "${FILES_TO_PACKAGE[@]}"; do
    if [ -d "$EXTENSION_PATH/$file" ]; then
        cp -r "$EXTENSION_PATH/$file" "$TEMP_DIR/"
    else
        cp "$EXTENSION_PATH/$file" "$TEMP_DIR/"
    fi
done

# Create ZIP archive
echo -e "\033[1;32m🗜️  Creating ZIP archive...\033[0m"
cd "$TEMP_DIR"
zip -r "$OUTPUT_ZIP" . -q

# Get package info
ZIP_SIZE=$(du -h "$OUTPUT_ZIP" | cut -f1)

# Success message
echo ""
echo -e "\033[1;32m✅ Extension package created successfully!\033[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\033[1;37m📍 Location: \033[1;33m$OUTPUT_ZIP\033[0m"
echo -e "\033[1;37m📊 Size: \033[1;33m$ZIP_SIZE\033[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""
echo -e "\033[1;36m📋 Next Steps:\033[0m"
echo -e "\033[1;37m  1. Test: Load unpacked in chrome://extensions/\033[0m"
echo -e "\033[1;37m  2. Upload to GitHub Releases (tag: v2.0.0-beta)\033[0m"
echo -e "\033[1;37m  3. Or submit to Chrome Web Store\033[0m"
echo ""
