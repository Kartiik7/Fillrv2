# Icon Files Required

The extension requires three icon files for proper display in Chrome:

- `icon16.png` (16x16 pixels)
- `icon48.png` (48x48 pixels)
- `icon128.png` (128x128 pixels)

## Quick Solution: Create Icons

### Option 1: Use Online Icon Generator
1. Visit: https://www.favicon-generator.org/
2. Upload any image or create a simple design
3. Download the generated icons
4. Rename them to `icon16.png`, `icon48.png`, `icon128.png`
5. Place them in the `extension/` folder

### Option 2: Use a Simple Image
1. Create a simple 128x128 image with any tool (Paint, Photoshop, etc.)
2. Use a purple gradient background (#667eea to #764ba2)
3. Add a white "F" or form icon in the center
4. Resize to create 16x16 and 48x48 versions
5. Save as PNG files

### Option 3: Temporary Workaround
For testing purposes, you can temporarily remove the icon references from `manifest.json`:

Remove these lines from `manifest.json`:
```json
"default_icon": {
  "16": "icon16.png",
  "48": "icon48.png",
  "128": "icon128.png"
},
```

And:
```json
"icons": {
  "16": "icon16.png",
  "48": "icon48.png",
  "128": "icon128.png"
}
```

The extension will still work, just without custom icons.

## Recommended Design
- **Background**: Purple gradient (#667eea to #764ba2)
- **Symbol**: White "F" letter or a simple form/document icon
- **Style**: Flat, modern, minimal

---

**Note**: Icons are optional for testing. The extension will function without them, but Chrome will show a default puzzle piece icon instead.
