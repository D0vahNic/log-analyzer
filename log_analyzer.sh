#!/bin/bash

file=$1

if [[ -z "$file" ]]; then
    echo "Usage: $0 <logfile>"
    exit 1
fi

if [[ ! -f "$file" ]]; then
    echo "File not found: $file"
    exit 1
fi


function overview {
	totalLines=$(wc -l < "$file")
	typeFile=$(file -b "$file")
	http200=$(grep -c "200" "$file")
	http404=$(grep -c "404" "$file")	
	http403=$(grep -c "403" "$file")
	http401=$(grep -c "401" "$file")

    echo '------------------------------------'
    echo "File name: $file"
    echo "File type: $typeFile"
    echo "Total Events Logged: $totalLines"
    echo "Total 200 HTTP returns: $http200"
    echo "Total 404 HTTP returns: $http404"
    echo "Total 403 HTTP returns: $http403"
    echo "Total 401 HTTP returns: $http401"
    echo '------------------------------------'
}

function ips {
	echo "IPs found:"
	awk '{print $1}' "$file" | sort | uniq -c | sort -nr
	echo '------------------------------------'
}

function top_ips {
    echo "Top 3 IPs:"
    awk '{print $1}' "$file" | sort | uniq -c | sort -nr | head -3
    echo '------------------------------------'
}

function top_user_agents {
    echo "Top 5 User-Agents:"
    awk -F\" '{print $6}' "$file" | sort | uniq -c | sort -nr | head -5
    echo '------------------------------------'
}

function search_ioc {
    local description=$1
    local regex=$2
    echo "$description"
    result=$(grep -Ei "$regex" "$file")
    if [[ -n "$result" ]]; then
        echo "$result"
    else
        echo "No matches found."
    fi
    echo '------------------------------------'
}

function ioc_sql_injection {
    search_ioc "Possible SQL Injection attempts:" "union.*select|select.+from|or 1=1|--|xp_cmdshell"
}

function ioc_xss {
    search_ioc "Possible XSS attempts:" "<script>|onerror=|javascript:"
}

function ioc_lfi_rfi {
    search_ioc "Possible LFI/RFI attempts:" "\.\./|\.\.\\|/etc/passwd|file=|http://"
}

function ioc_cmd_injection {
    search_ioc "Possible Command Injection attempts:" "; *ls|; *cat|; *whoami|&&| \| "
}



overview
ips
top_ips
top_user_agents
ioc_sql_injection
ioc_xss 
ioc_lfi_rfi
ioc_cmd_injection

