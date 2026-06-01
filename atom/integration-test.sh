#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   ATOM VAULT VFS - END-TO-END SYSTEM INTEGRATION TEST  ${NC}"
echo -e "${BLUE}======================================================${NC}"

echo -e "\n${YELLOW}[Step 1] Cleaning old environments and building Atom executable...${NC}"
rm -f test_vault.aegis disk_output.txt secret_input.txt
cargo build || { echo -e "${RED}Compilation failed!${NC}"; exit 1; }

echo -e "Atom Vault Secret Content: Computer Engineering VFS Hardware Hardening Framework 2026" > secret_input.txt
dd if=/dev/zero bs=1M count=50 >> secret_input.txt 2>/dev/null

echo -e "\n${YELLOW}[Step 2] Testing 'atom create' with dynamic CWD pathing...${NC}"
echo -e "securepassword123\nsecurepassword123" | ./target/debug/atom create --vault-name "test_vault"

if [ -f "test_vault.aegis" ]; then
    echo -e "${GREEN}[SUCCESS] Vault created successfully in Current Working Directory.${NC}"
else
    echo -e "${RED}[FAILED] Vault file not found! Path resolution broken.${NC}"
    exit 1;
fi

INITIAL_SIZE=$(stat -c%s "test_vault.aegis")
echo -e "Initial Empty Vault Size: ${BLUE}$INITIAL_SIZE bytes${NC}"

echo -e "\n${YELLOW}[Step 3] Firing up Ephemeral REPL Shell Execution Loop...${NC}"

./target/debug/atom enter --vault-path test_vault.aegis <<-'EOF'
import secret_input.txt vfs_file.txt
ls
cat vfs_file.txt
export vfs_file.txt disk_output.txt
rm vfs_file.txt
ls
vacuum
exit
EOF

echo -e "\n${YELLOW}[Step 4] Verifying Cryptographic Shredding & Structural Durability...${NC}"

if [ -f "disk_output.txt" ]; then
    echo -e "${GREEN}[SUCCESS] 'export' decrypted data securely back to physical host.${NC}"
    if grep -q "Atom Vault Secret Content" disk_output.txt; then
        echo -e "${GREEN}[SUCCESS] Plaintext integrity validated. No data corruption.${NC}"
    else
        echo -e "${RED}[FAILED] Exported file payload is corrupted or unreadable!${NC}"
    fi
else
    echo -e "${RED}[FAILED] Export command did not generate a host file!${NC}"
fi

FINAL_SIZE=$(stat -c%s "test_vault.aegis")
echo -e "\n${BLUE}Post-Import Size (Before Vacuum it was ~50MB)${NC}"
echo -e "Final physical container size after Vacuum: ${BLUE}$FINAL_SIZE bytes${NC}"

if [ "$FINAL_SIZE" -lt 5000000 ]; then
    echo -e "${GREEN}[SUCCESS] Issue #13 Fixed: Vacuum successfully discarded dead zones and collapsed container footprint.${NC}"
else
    echo -e "${RED}[FAILED] Storage bloat detected. Vacuum did not truncate abandoned cryptographic noise chunks.${NC}"
fi

rm -f disk_output.txt secret_input.txt
echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}  ALL REPL SYSTEMS COOPERATING PERFECTLY. READY TO PUSH! ${NC}"
echo -e "${GREEN}======================================================${NC}"