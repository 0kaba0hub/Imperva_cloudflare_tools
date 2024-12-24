when CLIENT_ACCEPTED {
  if { not ([class match [IP::client_addr] equals IP_Cloudflare_Whitelist]) } {
    log local0. "[IP::client_addr] is not permitted"
    drop
  }
}
