# Demo asset

`demo.svg` is a self-contained animated terminal recording used in the top-level
README. It is generated from **real** command output — not hand-written — so it
always reflects what the bashkit sandbox actually produces.

## Regenerating

1. Capture real output by running the demo commands through the actual sandbox
   (`create_bash`, the same entry point the server uses):

   ```bash
   cd ../crates/supabase-ssh
   DOCS_DIR=/path/to/docs cargo run --example capture_demo > ../assets/capture.txt
   ```

   The example lives at `crates/supabase-ssh/examples/capture_demo.rs`.
   `capture.txt` in this folder is the checked-in capture used for the current SVG.

2. Render the animated SVG (pure Python stdlib, no dependencies):

   ```bash
   python3 gen_demo.py capture.txt demo.svg
   ```

The animation uses CSS `@keyframes` (opacity reveal), which renders inline on
GitHub with no external hosting.
