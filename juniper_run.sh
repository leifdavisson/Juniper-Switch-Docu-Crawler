#!/bin/bash
# Interactive Operator Shell for Juniper Switch Docu-Crawler (Linux/macOS)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear_console() {
    clear
}

show_header() {
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${GREEN}          Juniper Switch Docu-Crawler - Linux/macOS Shell       ${NC}"
    echo -e "${CYAN}================================================================${NC}"
}

check_requirements() {
    echo -e "${CYAN}Checking requirements...${NC}"
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python3 is NOT installed. Please install it first.${NC}"
        return 1
    fi
    echo -e "${GREEN}[✓] Python3 detected: $(python3 --version)${NC}"
    return 0
}

install_dependencies() {
    echo -e "${CYAN}Installing Python packages from requirements.txt...${NC}"
    python3 -m pip install --upgrade pip
    if python3 -m pip install -r requirements.txt; then
         echo -e "${GREEN}[✓] Dependencies successfully installed!${NC}"
    else
         echo -e "${RED}[!] Dependency installation failed.${NC}"
    fi
}

run_discovery() {
    echo -e "${CYAN}Starting Juniper Switch Network Discovery Scan...${NC}"
    python3 juniper_crawler.py
}

retry_scan() {
    if [ -f juniper_failed_hosts.json ]; then
         echo -e "${CYAN}Resuming scan for failed hosts using juniper_failed_hosts.json...${NC}"
         python3 juniper_crawler.py --retry juniper_failed_hosts.json
    else
         echo -e "${YELLOW}[!] No juniper_failed_hosts.json found. No previous failed scans to resume.${NC}"
    fi
}

list_backups() {
    echo -e "${CYAN}Checking configuration backups...${NC}"
    if [ -d "outputs" ]; then
         cfgs=$(find outputs -path "*/backups/*.cfg" 2>/dev/null)
         if [ -n "$cfgs" ]; then
             echo "----------------------------------------------------------------"
             for f in $cfgs; do
                 echo -e "${GREEN}$(basename "$f") (${NC}$(wc -c < "$f" | xargs) bytes${GREEN})${NC}"
             done
             echo "----------------------------------------------------------------"
         else
             echo -e "${YELLOW}[!] No backup configurations (.cfg) found in the outputs/ directory.${NC}"
         fi
    else
         echo -e "${YELLOW}[!] The outputs/ directory does not exist. Run a successful scan first.${NC}"
    fi
}

save_baseline() {
    read -p "Enter baseline output filename [default: juniper_baseline.json]: " file
    file=${file:-juniper_baseline.json}
    echo -e "${CYAN}Starting scan and saving state to $file...${NC}"
    python3 juniper_crawler.py --save-baseline "$file"
}

compare_baseline() {
    read -p "Enter baseline input filename [default: juniper_baseline.json]: " file
    file=${file:-juniper_baseline.json}
    if [ ! -f "$file" ]; then
         echo -e "${RED}[!] Baseline file $file does not exist. Save a baseline first.${NC}"
         return
    fi
    echo -e "${CYAN}Starting scan and comparing state to $file...${NC}"
    python3 juniper_crawler.py --compare-baseline "$file"
}

install_nmap() {
    echo -e "${CYAN}Checking if Nmap is installed...${NC}"
    if command -v nmap &> /dev/null; then
         echo -e "${GREEN}[✓] Nmap is already installed.${NC}"
         return
    fi
    echo -e "${CYAN}Attempting to install Nmap using package manager...${NC}"
    if command -v apt-get &> /dev/null; then
         sudo apt-get update && sudo apt-get install -y nmap
    elif command -v yum &> /dev/null; then
         sudo yum install -y nmap
    elif command -v brew &> /dev/null; then
         brew install nmap
    else
         echo -e "${RED}[!] Unknown package manager. Please download Nmap manually from: https://nmap.org/${NC}"
    fi
}

while true; do
    clear_console
    show_header
    check_requirements
    
    echo ""
    echo -e "${CYAN}Operations Menu:${NC}"
    echo -e "  1) ${GREEN}Initialize Environment${NC} (Install Python + Crawler Packages)"
    echo -e "  2) ${GREEN}Run New Discovery Scan${NC}"
    echo -e "  3) ${GREEN}Retry/Resume Failed Devices${NC} (Loads juniper_failed_hosts.json)"
    echo -e "  4) ${GREEN}List Current Backups${NC}"
    echo -e "  5) ${GREEN}Save Baseline State${NC}"
    echo -e "  6) ${GREEN}Run Discovery & Compare to Baseline${NC}"
    echo -e "  7) ${GREEN}Install Nmap Utility${NC} (Optional)"
    echo -e "  8) ${RED}Exit${NC}"
    echo "----------------------------------------------------------------"
    
    read -p "Select option (1-8): " selection
    
    case $selection in
        1) install_dependencies ;;
        2) run_discovery ;;
        3) retry_scan ;;
        4) list_backups ;;
        5) save_baseline ;;
        6) compare_baseline ;;
        7) install_nmap ;;
        8)
            echo -e "\n${GREEN}Exiting Linux/macOS Operator Shell. Goodbye!${NC}\n"
            break
            ;;
        *)
            echo -e "${RED}[!] Invalid selection. Please choose a number between 1 and 8.${NC}"
            ;;
    esac
    
    echo -e "\nPress [Enter] to return to the menu..."
    read -r
done
