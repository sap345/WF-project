#!/bin/bash

# Check if the user is running the script as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "This script must be run as root!"
    exit 1
fi

# Check for necessary tools and install if missing
function check_tools {
    tools=("bulk_extractor" "binwalk" "foremost" "strings" "tcpdump" "bc" "tree" "ent")
    for tool in "${tools[@]}"; do
        if ! command -v $tool &> /dev/null; then
            echo -e "$tool is not installed. Installing.."
            sudo apt-get install -y $tool >/dev/null
        else
            echo -e "$tool is already installed."
        fi
    done
}

check_tools

# Get the user input for the file and the analysis type
echo -e "Enter the file path (Memory or HDD):"
read FILE 

if [ ! -f "$FILE" ]; then
    echo -e "File not found! Exiting..."
    exit 1
fi

# Ask user to select file type for analysis (Memory or HDD)
echo -e "Select M[Memory File] or H[HDD File]:"
read SEL

# Start a timer to track the analysis duration
START_TIME=$(date +%s)

# Initialize the report file
REPORT="analysis_report.txt"
echo "Analysis Report" > $REPORT
echo "File analyzed: $FILE" >> $REPORT
echo "Analysis started at: $(date)" >> $REPORT

# Function to extract network traffic
function extract_network_traffic {
    echo -e "Attempting to extract network traffic..." | tee -a $REPORT
    tcpdump -r $FILE -w extracted_network.pcap 2>/dev/null
    if [ -f "extracted_network.pcap" ]; then
        echo -e "Network traffic extracted and saved to extracted_network.pcap" | tee -a $REPORT
        echo -e "Size of extracted traffic: $(du -h extracted_network.pcap | cut -f1)" | tee -a $REPORT
    else
        echo -e "No network traffic found in the file." | tee -a $REPORT
    fi
}

# Functions for Memory analysis
function BULK() {
    echo "Running Bulk-Extractor on Memory file..." | tee -a $REPORT
    bulk_extractor $FILE -o BulkMEM 1>/dev/null
    echo "Bulk-Extractor completed." | tee -a $REPORT
}

function BINWALK() {
    echo "Running Binwalk on Memory file..." | tee -a $REPORT
    binwalk $FILE > BinwalkMEM 2>/dev/null 
    echo "Binwalk completed." | tee -a $REPORT
}

function FOREMOST() {
    echo "Running Foremost on Memory file..." | tee -a $REPORT
    foremost $FILE -o ForemostMEM 2>/dev/null 
    echo "Foremost completed." | tee -a $REPORT
}

function STRINGS() {
    echo "Running Strings on Memory file..." | tee -a $REPORT
    strings $FILE > StringsMEM 2>/dev/null 
    echo "Strings completed." | tee -a $REPORT
}

function VOL() {
    echo "Running Volatility on Memory file..." | tee -a $REPORT
    python3 vol.py -f $FILE imageinfo > VolMEM_profile.txt 2>/dev/null
    profile=$(grep "Suggested Profile" VolMEM_profile.txt | cut -d ':' -f2 | xargs)
    
    if [ -z "$profile" ]; then
        echo "Could not determine memory profile." | tee -a $REPORT
    else
        echo "Using profile: $profile" | tee -a $REPORT
        python3 vol.py -f $FILE --profile=$profile pslist > VolMEM_pslist.txt 2>/dev/null
        python3 vol.py -f $FILE --profile=$profile netscan > VolMEM_netscan.txt 2>/dev/null
        python3 vol.py -f $FILE --profile=$profile hivelist > VolMEM_registry.txt 2>/dev/null
        echo "Volatility analysis completed." | tee -a $REPORT
    fi
}

# Functions for HDD analysis
function BULK2() {
    echo "Running Bulk-Extractor on HDD file..." | tee -a $REPORT
    bulk_extractor $FILE -o BulkHDD 1>/dev/null
    echo "Bulk-Extractor completed." | tee -a $REPORT
}

function BINWALK2() {
    echo "Running Binwalk on HDD file..." | tee -a $REPORT
    binwalk $FILE > BinwalkHDD 2>/dev/null
    echo "Binwalk completed." | tee -a $REPORT
}

function FOREMOST2() {
    echo "Running Foremost on HDD file..." | tee -a $REPORT
    foremost $FILE -o ForemostHDD 2>/dev/null 
    echo "Foremost completed." | tee -a $REPORT
}

function STRINGS2() {
    echo "Running Strings on HDD file..." | tee -a $REPORT
    strings $FILE > StringsHDD 2>/dev/null
    echo "Strings completed." | tee -a $REPORT
}

# Function to calculate entropy (to find encrypted/compressed files)
function calculate_entropy {
    echo -e "Calculating entropy of the files..." | tee -a $REPORT
    ent $FILE >> $REPORT
}

# log function for Memory analysis
function LOGMEM() {
    mkdir -p memory_results
    mv BulkMEM BinwalkMEM ForemostMEM StringsMEM VolMEM* memory_results 2>/dev/null
    
    echo "Generating statistics for memory analysis..." | tee -a $REPORT

    # Calculate more detailed statistics
    echo "Number of text files: $(find memory_results -name '*.txt' | wc -l)" | tee -a $REPORT
    echo "Number of executable files: $(find memory_results -name '*.exe' | wc -l)" | tee -a $REPORT
    echo "Number of zip files: $(find memory_results -name '*.zip' | wc -l)" | tee -a $REPORT
    echo "Number of image files: $(find memory_results -name '*.jpg' -or -name '*.png' -or -name '*.gif' | wc -l)" | tee -a $REPORT
    echo "Number of PDF files: $(find memory_results -name '*.pdf' | wc -l)" | tee -a $REPORT
    echo "Number of video files (mp4, avi): $(find memory_results -name '*.mp4' -or -name '*.avi' | wc -l)" | tee -a $REPORT

    # Largest files
    echo "Top 5 largest files:" | tee -a $REPORT
    find memory_results -type f -exec du -h {} + | sort -rh | head -5 | tee -a $REPORT

    echo "Calculating entropy for memory file..." | tee -a $REPORT
    calculate_entropy

    echo "Saving the results into a zip file..." | tee -a $REPORT
    zip -r memory_results.zip memory_results 1>/dev/null

    echo "Memory analysis results saved." | tee -a $REPORT
}

# Enhanced log function for HDD analysis
function LOGHDD() {
    mkdir -p hdd_results
    mv BulkHDD BinwalkHDD ForemostHDD StringsHDD hdd_results 2>/dev/null
    
    echo "Generating statistics for HDD analysis..." | tee -a $REPORT

    # Calculate more detailed statistics
    echo "Number of text files: $(find hdd_results -name '*.txt' | wc -l)" | tee -a $REPORT
    echo "Number of executable files: $(find hdd_results -name '*.exe' | wc -l)" | tee -a $REPORT
    echo "Number of zip files: $(find hdd_results -name '*.zip' | wc -l)" | tee -a $REPORT
    echo "Number of image files: $(find hdd_results -name '*.jpg' -or -name '*.png' -or -name '*.gif' | wc -l)" | tee -a $REPORT
    echo "Number of PDF files: $(find hdd_results -name '*.pdf' | wc -l)" | tee -a $REPORT
    echo "Number of video files (mp4, avi): $(find hdd_results -name '*.mp4' -or -name '*.avi' | wc -l)" | tee -a $REPORT

    # Largest files
    echo "Top 5 largest files:" | tee -a $REPORT
    find hdd_results -type f -exec du -h {} + | sort -rh | head -5 | tee -a $REPORT

    echo "Calculating entropy for HDD file..." | tee -a $REPORT
    calculate_entropy

    echo "Saving the results into a zip file..." | tee -a $REPORT
    zip -r hdd_results.zip hdd_results 1>/dev/null

    echo "HDD analysis results saved." | tee -a $REPORT
}

# Execute analysis based on user selection
case $SEL in
    M)
        BULK
        BINWALK
        FOREMOST
        STRINGS
        VOL
        extract_network_traffic
        LOGMEM
        ;;
    H)
        BULK2
        BINWALK2
        FOREMOST2
        STRINGS2
        extract_network_traffic
        LOGHDD
        ;;
    *)
        echo -e "Invalid selection. Exiting..."
        exit 1
        ;;
esac

# Calculate the time taken for analysis
END_TIME=$(date +%s)
ELAPSED_TIME=$(($END_TIME - $START_TIME))
echo -e "Analysis completed in $ELAPSED_TIME seconds." | tee -a $REPORT

# Save general statistics into the report file
echo "Analysis Summary" >> $REPORT
echo "Time taken: $ELAPSED_TIME seconds" >> $REPORT
echo "Results saved as: memory_results.zip or hdd_results.zip" >> $REPORT

echo -e "mAll results and report have been saved successfully."
