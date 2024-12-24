when HTTP_REQUEST {
    # Check if the X-Forwarded-For header exists
    if { [HTTP::header exists "X-Forwarded-For"] } {
        # Get the first IP from the X-Forwarded-For header (in case there are multiple, separated by commas)
        set xff_ip [lindex [split [HTTP::header "X-Forwarded-For"] ","] 0]

        # Check if the IP in the X-Forwarded-For header is in the Imperva IP ranges
        if { [class match $xff_ip equals IP_Imperva_Whitelist] } {
            # Replace the IP in the X-Forwarded-For header with the client's IP address
            HTTP::header replace "X-Forwarded-For" [IP::client_addr]
        }
    } else {
        # If the X-Forwarded-For header does not exist, add it with the client's IP address
        HTTP::header insert "X-Forwarded-For" [IP::client_addr]
    }
}
