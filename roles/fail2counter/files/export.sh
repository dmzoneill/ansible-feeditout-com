#!/bin/bash

OUTPUT_FILE="metasploit_exploits_with_options.txt"
TEMP_CMDS="msf_temp_commands.rc"

echo "[*] Starting export of all Metasploit exploits and their required options..."
echo "[*] Output will be saved to: $OUTPUT_FILE"

# Get the list of all exploit module paths
/opt/metasploit-framework/bin/msfconsole -q -x "show exploits; exit" | grep 'exploit/' | awk '{print $2}' > exploits.txt

# Clean output file
echo "" > "$OUTPUT_FILE"

# Loop through each exploit module
while read -r exploit; do
    echo "[+] Processing: $exploit"

    # Write temporary msfconsole script
    {
        echo "use $exploit"
        echo "show options"
        echo "exit"
    } > "$TEMP_CMDS"

    # Run msfconsole with this module and append output to file
    echo "===== $exploit =====" >> "$OUTPUT_FILE"
    /opt/metasploit-framework/bin/msfconsole -q -r "$TEMP_CMDS" >> "$OUTPUT_FILE"
    echo -e "\n\n" >> "$OUTPUT_FILE"

done < exploits.txt

# Cleanup
rm -f "$TEMP_CMDS" exploits.txt

echo "[*] Done! All exploit details saved in $OUTPUT_FILE"
